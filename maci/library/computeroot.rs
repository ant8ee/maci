use super::hasher::Hasher;

pub struct ComputeRoot;
impl ComputeRoot {
    const LEAVES_PER_NODE: u8 = 5;

    pub fn compute_empty_root(tree_levels: u8, zero_value: [u8; 32]) -> [u8; 32] {
        // Limit the Merkle tree to MAX_DEPTH levels
        assert!(
            tree_levels > 0 && tree_levels <= 32,
            "Compute_root: tree_levels must be between 0 and 33"
        );

        let mut current_zero = zero_value;
        for _ in 1..tree_levels {
            let hashed = Hasher::hash_left_right(current_zero, current_zero);
            current_zero = hashed;
        }

        Hasher::hash_left_right(current_zero, current_zero)
    }

    pub fn compute_empty_quin_root(tree_levels: u8, zero_value: [u8; 32]) -> [u8; 32] {
        // Limit the Merkle tree to MAX_DEPTH levels
        assert!(
            tree_levels > 0 && tree_levels <= 32,
            "Compute_root: tree_levels must be between 0 and 33"
        );

        let mut current_zero = zero_value;

        for _ in 0..tree_levels {
            let z = [current_zero; Self::LEAVES_PER_NODE as usize];
            current_zero = Hasher::hash5(z);
        }

        current_zero
    }
}
