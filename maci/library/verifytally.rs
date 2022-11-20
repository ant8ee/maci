use ink_prelude::{vec, vec::Vec};

pub struct VerifyTally;
use super::hasher::Hasher;
impl VerifyTally {
    const LEAVES_PER_NODE: u8 = 5;

    pub fn compute_merkle_root_from_path(
        _depth: u8,
        index: u128,
        _leaf: [u8; 32],
        _path_elements: Vec<Vec<[u8; 32]>>,
    ) -> [u8; 32] {
        let n = Self::LEAVES_PER_NODE as usize;
        let mut _index = index as usize;
        let mut pos = _index % n;
        let mut current = _leaf;
        let mut k;

        let mut level = [[0u8; 32]; 5];

        for i in 0.._depth as usize {
            for j in 0..n {
                if j == pos {
                    level[j] = current;
                } else {
                    if j > pos {
                        k = j - 1;
                    } else {
                        k = j;
                    }
                    level[j] = _path_elements[i][k];
                }
            }

            _index /= n;
            pos = _index % n;
            current = Hasher::hash5(level);
        }

        current
    }
}
