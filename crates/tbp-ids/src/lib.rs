use std::borrow::Borrow;
use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_id!(ContextId);
define_id!(TokenPathId);
define_id!(WitnessId);
define_id!(RefId);
define_id!(PackId);

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::TokenPathId;

    #[test]
    fn token_path_id_supports_set_lookup_by_str() {
        let mut ids = BTreeSet::new();
        ids.insert(TokenPathId::from("color.surface.bg"));
        assert!(ids.contains("color.surface.bg"));
        assert!(!ids.contains("color.surface.fg"));
    }
}
