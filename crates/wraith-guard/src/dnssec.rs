//! Local DNSSEC validation; every validation query uses the same Tor DoH path.
use crate::dns_engine::SovereignDnsServer;
use futures_util::{stream, Stream, StreamExt};
use hickory_net::{
    dnssec::DnssecDnsHandle,
    proto::{
        dnssec::Proof,
        op::{
            DnsRequest, DnsRequestOptions, DnsResponse, Message, MessageType, OpCode, ResponseCode,
        },
        rr::{DNSClass, RecordType},
    },
    runtime::TokioRuntimeProvider,
    xfer::DnsHandle,
    NetError,
};
use std::pin::Pin;
use wraith_core::error::{Result, WraithError};

#[derive(Clone)]
struct TorDoh {
    url: String,
}
impl DnsHandle for TorDoh {
    type Runtime = TokioRuntimeProvider;
    type Response = Pin<Box<dyn Stream<Item = std::result::Result<DnsResponse, NetError>> + Send>>;
    fn send(&self, request: DnsRequest) -> Self::Response {
        let url = self.url.clone();
        Box::pin(stream::once(async move {
            let query = request.to_vec().map_err(NetError::from)?;
            let bytes = SovereignDnsServer::query_doh(&url, &query)
                .await
                .map_err(|e| NetError::Msg(e.to_string()))?;
            let response = DnsResponse::from_buffer(bytes)?;
            if response.id != request.id
                || response.queries != request.queries
                || response.op_code != request.op_code
                || response.truncation
            {
                return Err(NetError::Message("Invalid DoH response envelope"));
            }
            Ok(response)
        }))
    }
}

pub(crate) async fn resolve(url: &str, query: &[u8]) -> Result<Vec<u8>> {
    let mut request = Message::from_vec(query).map_err(|e| WraithError::Network(e.to_string()))?;
    if request.metadata.message_type != MessageType::Query
        || request.op_code != OpCode::Query
        || request.queries.len() != 1
        || request.queries[0].query_class != DNSClass::IN
    {
        return Err(WraithError::Network(
            "Only single-question IN-class DNS queries are supported".into(),
        ));
    }
    let id = request.id;
    // A client's CD flag must not disable this gateway's validation policy.
    request.metadata.checking_disabled = false;
    request.metadata.authentic_data = false;
    let validator = DnssecDnsHandle::new(TorDoh { url: url.into() }).validation_cache_size(256);
    let mut replies = validator.send(DnsRequest::new(request, DnsRequestOptions::default()));
    let response = replies
        .next()
        .await
        .ok_or_else(|| WraithError::Network("DNSSEC returned no response".into()))?
        .map_err(|e| WraithError::Network(format!("DNSSEC validation failed: {e}")))?;
    let mut message = response.into_message();
    check_proofs(&mut message)?;
    message.metadata.id = id;
    message
        .to_vec()
        .map_err(|e| WraithError::Network(e.to_string()))
}

fn check_proofs(message: &mut Message) -> Result<()> {
    // Hickory attaches proof status to each RRset; Ok alone is not sufficient.
    let records: Vec<_> = message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .filter(|record| record.record_type() != RecordType::RRSIG)
        .collect();
    if records
        .iter()
        .any(|record| matches!(record.proof, Proof::Bogus | Proof::Indeterminate))
    {
        return Err(WraithError::Network(
            "Unvalidated DNSSEC answer or authority record".into(),
        ));
    }
    message.metadata.authentic_data =
        !records.is_empty() && records.iter().all(|record| record.proof == Proof::Secure);
    message.metadata.checking_disabled = false;
    // Never forward unvalidated glue or other ancillary data to clients.
    message
        .additionals
        .retain(|record| matches!(record.proof, Proof::Secure | Proof::Insecure));
    Ok(())
}

pub(crate) fn servfail(query: &[u8]) -> Result<Vec<u8>> {
    let mut message = Message::from_vec(query)
        .map_err(|e| WraithError::Network(e.to_string()))?
        .into_response();
    message.metadata.response_code = ResponseCode::ServFail;
    message.metadata.authentic_data = false;
    message.metadata.checking_disabled = false;
    message.answers.clear();
    message.authorities.clear();
    message.additionals.clear();
    message
        .to_vec()
        .map_err(|e| WraithError::Network(e.to_string()))
}

pub(crate) fn fit_udp(query: &[u8], response: Vec<u8>) -> Result<Vec<u8>> {
    let query = Message::from_vec(query).map_err(|e| WraithError::Network(e.to_string()))?;
    let maximum = query
        .edns
        .as_ref()
        .map(|edns| edns.max_payload())
        .unwrap_or(512)
        .clamp(512, 4096) as usize;
    if response.len() <= maximum {
        return Ok(response);
    }
    let mut message =
        Message::from_vec(&response).map_err(|e| WraithError::Network(e.to_string()))?;
    message.metadata.truncation = true;
    message.answers.clear();
    message.authorities.clear();
    message.additionals.clear();
    message
        .to_vec()
        .map_err(|e| WraithError::Network(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::proto::rr::{rdata::A, Name, RData, Record};
    #[test]
    fn forged_ad_cannot_replace_validation_proof() {
        let mut message = Message::query().into_response();
        message.metadata.authentic_data = true;
        let mut record = Record::from_rdata(
            Name::from_ascii("example.org.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        );
        for proof in [Proof::Bogus, Proof::Indeterminate] {
            record.proof = proof;
            message.answers = vec![record.clone()];
            assert!(check_proofs(&mut message).is_err());
        }
        record.proof = Proof::Insecure;
        message.answers = vec![record.clone()];
        check_proofs(&mut message).unwrap();
        assert!(!message.authentic_data);
        record.proof = Proof::Secure;
        message.answers = vec![record];
        check_proofs(&mut message).unwrap();
        assert!(message.authentic_data);
    }
    #[derive(Clone)]
    struct ForgedResolver;
    impl DnsHandle for ForgedResolver {
        type Runtime = TokioRuntimeProvider;
        type Response =
            stream::Iter<std::vec::IntoIter<std::result::Result<DnsResponse, NetError>>>;
        fn send(&self, request: DnsRequest) -> Self::Response {
            let mut message = request.into_parts().0.into_response();
            message.metadata.authentic_data = true;
            if message.queries[0].query_type == RecordType::A {
                message.answers.push(Record::from_rdata(
                    message.queries[0].name.clone(),
                    60,
                    RData::A(A::new(192, 0, 2, 1)),
                ));
            }
            stream::iter(vec![Ok(DnsResponse::from_buffer(
                message.to_vec().unwrap(),
            )
            .unwrap())])
        }
    }
    #[tokio::test]
    async fn real_validator_rejects_forged_root_answer() {
        let mut request = Message::query();
        request.queries.push(hickory_net::proto::op::Query::query(
            Name::root(),
            RecordType::A,
        ));
        let validator = DnssecDnsHandle::new(ForgedResolver);
        let result = validator
            .send(DnsRequest::new(request, DnsRequestOptions::default()))
            .next()
            .await
            .unwrap();
        if let Ok(response) = result {
            assert!(check_proofs(&mut response.into_message()).is_err());
        }
    }
    #[test]
    fn oversized_udp_reply_requests_tcp_and_servfail_clears_proofs() {
        let mut request = Message::query();
        request.metadata.id = 123;
        request.metadata.checking_disabled = true;
        request.metadata.authentic_data = true;
        request.queries.push(hickory_net::proto::op::Query::query(
            Name::root(),
            RecordType::A,
        ));
        let query = request.to_vec().unwrap();
        let mut response = request.into_response();
        for _ in 0..60 {
            response.answers.push(Record::from_rdata(
                Name::root(),
                60,
                RData::A(A::new(192, 0, 2, 1)),
            ));
        }
        let shortened = fit_udp(&query, response.to_vec().unwrap()).unwrap();
        assert!(shortened.len() <= 512);
        assert!(Message::from_vec(&shortened).unwrap().truncation);
        let failure = Message::from_vec(&servfail(&query).unwrap()).unwrap();
        assert_eq!(failure.id, 123);
        assert_eq!(failure.response_code, ResponseCode::ServFail);
        assert!(!failure.authentic_data && !failure.checking_disabled);
    }
}
