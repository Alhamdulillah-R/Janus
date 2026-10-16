use bytes::Bytes;

/// Huffman coding choice for HPACK string literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Huffman {
    /// Always Huffman-encode non-empty strings (h2 crate behaviour)
    Always,
    /// Never Huffman-encode
    Never,
    /// Huffman-encode only when it is strictly shorter than the raw octets
    IfShorter,
}

/// Representation for a header field that is not already fully indexed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Indexing {
    /// Literal with incremental indexing (inserted into the dynamic table)
    Incremental,
    /// Literal without indexing
    WithoutIndexing,
    /// Literal never indexed
    NeverIndexed,
}

/// HPACK encoding policy for outgoing header blocks.
#[derive(Clone, Debug)]
pub struct HpackPolicy {
    huffman: Huffman,
    default_indexing: Indexing,
    rules: Vec<(Bytes, Indexing)>,
    crumble_cookies: bool,
}

impl HpackPolicy {
    /// Policy with one Huffman mode and one indexing mode for every field.
    pub fn new(huffman: Huffman, default_indexing: Indexing) -> Self {
        HpackPolicy {
            huffman,
            default_indexing,
            rules: Vec::new(),
            crumble_cookies: false,
        }
    }

    /// Chromium's encoder: index everything except pseudo-headers other than :authority, Huffman only when shorter, cookies split into crumbs.
    pub fn chrome() -> Self {
        HpackPolicy::new(Huffman::IfShorter, Indexing::Incremental)
            .rule(":method", Indexing::WithoutIndexing)
            .rule(":scheme", Indexing::WithoutIndexing)
            .rule(":path", Indexing::WithoutIndexing)
            .rule(":protocol", Indexing::WithoutIndexing)
            .rule(":status", Indexing::WithoutIndexing)
            .crumble_cookies(true)
    }

    /// Override the indexing mode for one header name (lowercase, pseudo-headers with the leading ':').
    pub fn rule(mut self, name: &str, indexing: Indexing) -> Self {
        let name = Bytes::copy_from_slice(name.to_ascii_lowercase().as_bytes());

        self.rules.retain(|(n, _)| *n != name);
        self.rules.push((name, indexing));
        self
    }

    /// Split `cookie` values on ';' into separate fields before encoding.
    pub fn crumble_cookies(mut self, enabled: bool) -> Self {
        self.crumble_cookies = enabled;
        self
    }

    /// Huffman mode in effect.
    pub fn huffman(&self) -> Huffman {
        self.huffman
    }

    /// Indexing mode for names without a rule.
    pub fn default_indexing(&self) -> Indexing {
        self.default_indexing
    }

    /// Per-name indexing overrides, in insertion order.
    pub fn rules(&self) -> impl Iterator<Item = (&[u8], Indexing)> {
        self.rules.iter().map(|(name, indexing)| (name.as_ref(), *indexing))
    }

    /// Whether cookie crumbling is enabled.
    pub fn crumbles_cookies(&self) -> bool {
        self.crumble_cookies
    }

    /// Indexing mode for a header name.
    pub fn indexing_for(&self, name: &[u8]) -> Indexing {
        for (n, indexing) in &self.rules {
            if n.as_ref() == name {
                return *indexing;
            }
        }
        self.default_indexing
    }
}
