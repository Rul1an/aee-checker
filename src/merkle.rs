//! DSSE PAE encoding and the RFC 6962 Merkle tree over observation records.

use sha2::{Digest, Sha256};

/// DSSE Pre-Authentication Encoding over (payloadType, payload bytes):
/// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// RFC 6962 leaf hash: SHA-256(0x00 || input).
pub fn leaf_hash(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(input);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// RFC 6962 Merkle tree root over precomputed leaf hashes, using the
/// recursive largest-power-of-two-less-than-n split. A single leaf's root
/// is the leaf hash itself. Never pads by duplicating a trailing node.
pub fn root_over_leaves(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    match leaves.len() {
        0 => None,
        1 => Some(leaves[0]),
        n => {
            let k = largest_power_of_two_below(n);
            let left = root_over_leaves(&leaves[..k]).unwrap();
            let right = root_over_leaves(&leaves[k..]).unwrap();
            Some(node_hash(&left, &right))
        }
    }
}

fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_shape() {
        assert_eq!(
            pae("application/x+json", b"{}"),
            b"DSSEv1 18 application/x+json 2 {}".to_vec()
        );
    }

    #[test]
    fn split_points() {
        assert_eq!(largest_power_of_two_below(2), 1);
        assert_eq!(largest_power_of_two_below(3), 2);
        assert_eq!(largest_power_of_two_below(4), 2);
        assert_eq!(largest_power_of_two_below(5), 4);
        assert_eq!(largest_power_of_two_below(8), 4);
    }

    #[test]
    fn three_leaf_tree_shape() {
        // MTH(3) = H(0x01 || MTH([0,1]) || MTH([2]))
        let l: Vec<[u8; 32]> = (0..3u8).map(|i| leaf_hash(&[i])).collect();
        let left = node_hash(&l[0], &l[1]);
        let expect = node_hash(&left, &l[2]);
        assert_eq!(root_over_leaves(&l).unwrap(), expect);
    }
}
