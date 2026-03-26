// ******************
//  Copyright 2025 Sean M. Brennan and contributors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
// ******************
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove as stark_prove, verify as stark_verify};
use pyo3::prelude::*;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};

// -- Type aliases for the STARK configuration --

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
type Challenge = BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, Challenge, Challenger>;

const NUM_COLS: usize = 2; // [value, running_sum]

/// AIR for task data integrity verification.
///
/// Proves knowledge of a sequence of field elements whose running sum
/// equals a claimed public value. The trace has two columns:
///   - col 0: the data element at this row
///   - col 1: the cumulative sum up to and including this row
struct TaskIntegrityAir;

impl<F> BaseAir<F> for TaskIntegrityAir {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for TaskIntegrityAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("empty trace");
        let next = main.row_slice(1).expect("trace has only 1 row");

        let value = local[0].clone();
        let running_sum = local[1].clone();
        let next_value = next[0].clone();
        let next_running_sum = next[1].clone();

        // First row constraint: running_sum == value
        builder
            .when_first_row()
            .assert_eq(running_sum.clone(), value);

        // Transition constraint: next_running_sum == running_sum + next_value
        builder
            .when_transition()
            .assert_eq(next_running_sum, running_sum.clone() + next_value);

        // Last row: running_sum must equal the public claimed sum
        let pv_val = builder.public_values()[0].clone();
        builder
            .when_last_row()
            .assert_eq(running_sum, pv_val);
    }
}

/// Build the Poseidon2 permutation with deterministic round constants.
fn build_perm() -> Perm {
    let mut rng = SmallRng::seed_from_u64(0x5441534B5F5A4B50); // "TASK_ZKP"
    Perm::new_from_rng_128(&mut rng)
}

/// Build the full STARK config.
fn build_stark_config() -> Config {
    let perm = build_perm();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = create_test_fri_params(challenge_mmcs, 0);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    Config::new(pcs, challenger)
}

/// Convert input bytes to BabyBear field elements, padding to a power of 2.
fn bytes_to_field_elements(data: &[u8]) -> Vec<Val> {
    // Pack bytes into field elements (3 bytes per element to stay within BabyBear modulus ~2^31)
    let mut elements: Vec<Val> = Vec::new();
    for chunk in data.chunks(3) {
        let mut val: u32 = 0;
        for (i, &b) in chunk.iter().enumerate() {
            val |= (b as u32) << (i * 8);
        }
        elements.push(BabyBear::new(val));
    }
    // Pad to at least 2 elements (minimum trace length for transitions)
    while elements.len() < 2 {
        elements.push(Val::ZERO);
    }
    // Pad to next power of 2
    let target_len = elements.len().next_power_of_two();
    elements.resize(target_len, Val::ZERO);
    elements
}

/// Build the execution trace for the AIR.
fn build_trace(elements: &[Val]) -> RowMajorMatrix<Val> {
    let n = elements.len();
    let mut trace_values = Vec::with_capacity(n * NUM_COLS);
    let mut running_sum = Val::ZERO;
    for &elem in elements {
        running_sum += elem;
        trace_values.push(elem);
        trace_values.push(running_sum);
    }
    RowMajorMatrix::new(trace_values, NUM_COLS)
}

#[derive(Serialize, Deserialize)]
struct SerializedProof {
    proof_bytes: Vec<u8>,
    public_sum: u32,
}

/// Generate a STARK proof for the given data bytes.
fn prove_inner(data: &[u8]) -> Result<Vec<u8>, String> {
    let elements = bytes_to_field_elements(data);

    // Compute the running sum (public value)
    let mut running_sum = Val::ZERO;
    for &elem in &elements {
        running_sum += elem;
    }

    let trace = build_trace(&elements);
    let config = build_stark_config();
    let public_values = vec![running_sum];

    let proof = stark_prove(&config, &TaskIntegrityAir, trace, &public_values);

    let serialized = SerializedProof {
        proof_bytes: bincode::serialize(&proof).map_err(|e| e.to_string())?,
        public_sum: running_sum.as_canonical_u32(),
    };

    bincode::serialize(&serialized).map_err(|e| e.to_string())
}

/// Verify a STARK proof.
fn verify_inner(proof_data: &[u8]) -> Result<bool, String> {
    let serialized: SerializedProof =
        bincode::deserialize(proof_data).map_err(|e| e.to_string())?;

    let proof = bincode::deserialize(&serialized.proof_bytes).map_err(|e| e.to_string())?;

    let public_sum = BabyBear::new(serialized.public_sum);
    let public_values = vec![public_sum];
    let config = build_stark_config();

    match stark_verify(&config, &TaskIntegrityAir, &proof, &public_values) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// -- PyO3 Python bindings --

/// Generate a ZK-STARK proof of data integrity for the given bytes.
#[pyfunction]
fn prove(data: &[u8]) -> PyResult<Vec<u8>> {
    prove_inner(data).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// Verify a ZK-STARK proof. Returns True if valid, False otherwise.
#[pyfunction]
fn verify(proof_data: &[u8]) -> PyResult<bool> {
    verify_inner(proof_data).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e))
}

/// ZK-STARK proof generation and verification for autonomous-trust task data integrity.
#[pymodule]
fn autonomous_trust_zkp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(prove, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify() {
        let data = b"hello world task data";
        let proof = prove_inner(data).expect("proving should succeed");
        assert!(verify_inner(&proof).expect("verification should succeed"));
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let proof = prove_inner(data).expect("proving empty data should succeed");
        assert!(verify_inner(&proof).expect("verification should succeed"));
    }

    #[test]
    fn test_tampered_proof_fails() {
        let data = b"task result data";
        let mut proof = prove_inner(data).expect("proving should succeed");
        let mid = proof.len() / 2;
        proof[mid] ^= 0xFF;
        match verify_inner(&proof) {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("tampered proof should not verify"),
        }
    }
}
