//! Owned recovery buffers: zeroization on normal drop, including error paths.
//! This does not cover abort/SIGKILL, allocator copies or third-party TLS memory.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HashMap itself cannot implement Zeroize: keys must be removed before wiping.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SensitiveMap<V: Zeroize>(HashMap<String, V>);

impl<V: Zeroize> Default for SensitiveMap<V> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}
impl<V: Zeroize> std::fmt::Debug for SensitiveMap<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SensitiveMap")
            .field("entries", &self.0.len())
            .finish_non_exhaustive()
    }
}
impl<V: Zeroize> From<HashMap<String, V>> for SensitiveMap<V> {
    fn from(value: HashMap<String, V>) -> Self {
        Self(value)
    }
}
impl<V: Zeroize> Deref for SensitiveMap<V> {
    type Target = HashMap<String, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<'a, V: Zeroize> IntoIterator for &'a SensitiveMap<V> {
    type Item = (&'a String, &'a V);
    type IntoIter = std::collections::hash_map::Iter<'a, String, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
impl<V: Zeroize> SensitiveMap<V> {
    pub fn insert(&mut self, key: String, value: V) {
        if let Some((mut previous_key, mut previous_value)) = self.0.remove_entry(&key) {
            previous_key.zeroize();
            previous_value.zeroize();
        }
        self.0.insert(key, value);
    }
    pub fn clear(&mut self) {
        self.zeroize();
    }
}
impl<V: Zeroize> Zeroize for SensitiveMap<V> {
    fn zeroize(&mut self) {
        for (mut key, mut value) in self.0.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}
impl<V: Zeroize> Drop for SensitiveMap<V> {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl<V: Zeroize> ZeroizeOnDrop for SensitiveMap<V> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};
    struct Probe {
        bytes: Vec<u8>,
        erased: Rc<Cell<usize>>,
    }
    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.erased.set(self.erased.get() + 1);
        }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            assert!(self.bytes.is_empty(), "value freed before zeroization");
        }
    }
    #[test]
    fn replacement_clear_and_error_drop_zeroize_owned_values() {
        let erased = Rc::new(Cell::new(0));
        let mut map = SensitiveMap::default();
        let probe = || Probe {
            bytes: vec![42; 32],
            erased: erased.clone(),
        };
        map.insert("key".into(), probe());
        map.insert("key".into(), probe());
        assert_eq!(erased.get(), 1);
        map.clear();
        assert_eq!(erased.get(), 2);
        let error_path = || -> Result<(), ()> {
            let mut map = SensitiveMap::default();
            map.insert("error".into(), probe());
            Err(())
        };
        assert!(error_path().is_err());
        assert_eq!(erased.get(), 3);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut map = SensitiveMap::default();
            map.insert("panic".into(), probe());
            panic!("simulated unwind");
        }));
        assert!(panic.is_err());
        assert_eq!(erased.get(), 4);
    }
    #[test]
    fn serialized_shape_stays_a_plain_map() {
        let mut map = SensitiveMap::default();
        map.insert("key".into(), String::from("secret"));
        let serialized = zeroize::Zeroizing::new(serde_json::to_string(&map).unwrap());
        assert_eq!(&*serialized, r#"{"key":"secret"}"#);
        let mut decoded: SensitiveMap<String> = serde_json::from_str(&serialized).unwrap();
        decoded.zeroize();
        assert!(decoded.is_empty());
    }
}
