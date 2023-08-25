use ark_ec::PairingEngine;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_serialize::*;
use ark_std::{
    io::{self, Result as IoResult},
    vec::Vec,
};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.a.write(&mut writer)?;
        self.b.write(&mut writer)?;
        self.c.write(&mut writer)
    }
}

impl<E: PairingEngine> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: PairingEngine> {
    /// The `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `E::G1`.
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> ToBytes for VerifyingKey<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.alpha_g1.write(&mut writer)?;
        self.beta_g2.write(&mut writer)?;
        self.gamma_g2.write(&mut writer)?;
        self.delta_g2.write(&mut writer)?;
        for q in &self.gamma_abc_g1 {
            q.write(&mut writer)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> VerifyingKey<E> {
    /// read
    pub fn read<R: Read>(mut reader: R, len: usize) -> Self {
        let alpha_g1 = E::G1Affine::read(&mut reader).unwrap();
        let beta_g2 = E::G2Affine::read(&mut reader).unwrap();
        let gamma_g2 = E::G2Affine::read(&mut reader).unwrap();
        let delta_g2 = E::G2Affine::read(&mut reader).unwrap();
        let mut gamma_abc_g1 = Vec::new();
        for _ in 0..len {
            let abc = E::G1Affine::read(&mut reader).unwrap();
            gamma_abc_g1.push(abc);
        }

        Self { alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_abc_g1 }
    }
}

impl<E: PairingEngine> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq)]
pub struct PreparedVerifyingKey<E: PairingEngine> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: E::Fqk,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: E::G2Prepared,
}

impl<E: PairingEngine> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: PairingEngine> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        crate::prepare_verifying_key(&other)
    }
}

impl<E: PairingEngine> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::Fqk::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
        }
    }
}

impl<E: PairingEngine> ToBytes for PreparedVerifyingKey<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write(&mut writer)?;
        self.alpha_g1_beta_g2.write(&mut writer)?;
        self.gamma_g2_neg_pc.write(&mut writer)?;
        self.delta_g2_neg_pc.write(&mut writer)?;
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// proving key size
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KeySize {
    /// vk len
    pub vk_len: usize,
    /// a_query len
    pub a_len: usize,
    /// b_g1_query len
    pub b_g1_len: usize,
    /// b_g2_query len
    pub b_g2_len: usize,
    /// h_query len
    pub h_len: usize,
    /// l_query len
    pub l_len: usize,
}

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: PairingEngine> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The elements `a_i * G` in `E::G1`.
    pub a_query: Vec<E::G1Affine>,
    /// The elements `b_i * G` in `E::G1`.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The elements `b_i * H` in `E::G2`.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The elements `h_i * G` in `E::G1`.
    pub h_query: Vec<E::G1Affine>,
    /// The elements `l_i * G` in `E::G1`.
    pub l_query: Vec<E::G1Affine>,
}

impl<E: PairingEngine> ToBytes for ProvingKey<E> {
    fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write(&mut writer)?;
        self.beta_g1.write(&mut writer)?;
        self.delta_g1.write(&mut writer)?;
        for q in &self.a_query {
            q.write(&mut writer)?;
        }
        for q in &self.b_g1_query {
            q.write(&mut writer)?;
        }
        for q in &self.b_g2_query {
            q.write(&mut writer)?;
        }
        for q in &self.h_query {
            q.write(&mut writer)?;
        }
        for q in &self.l_query {
            q.write(&mut writer)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> ProvingKey<E> {
    /// read
    pub fn read<R: Read>(mut reader: R, key_size: &KeySize) -> Self {
        let vk = VerifyingKey::<E>::read(&mut reader, key_size.vk_len);
        let beta_g1 = E::G1Affine::read(&mut reader).unwrap();
        let delta_g1 = E::G1Affine::read(&mut reader).unwrap();
        
        let mut a_query = Vec::new();
        for _ in 0..key_size.a_len {
            let q = E::G1Affine::read(&mut reader).unwrap();
            a_query.push(q);
        }

        let mut b_g1_query = Vec::new();
        for _ in 0..key_size.b_g1_len {
            let q = E::G1Affine::read(&mut reader).unwrap();
            b_g1_query.push(q);
        }

        let mut b_g2_query = Vec::new();
        for _ in 0..key_size.b_g2_len {
            let q = E::G2Affine::read(&mut reader).unwrap();
            b_g2_query.push(q);
        }

        let mut h_query = Vec::new();
        for _ in 0..key_size.h_len {
            let q = E::G1Affine::read(&mut reader).unwrap();
            h_query.push(q);
        }

        let mut l_query = Vec::new();
        for _ in 0..key_size.l_len {
            let q = E::G1Affine::read(&mut reader).unwrap();
            l_query.push(q);
        }

        Self { vk, beta_g1, delta_g1, a_query, b_g1_query, b_g2_query, h_query, l_query }
    }
    
    /// size
    pub fn size(&self) -> KeySize {
        KeySize { 
            vk_len: self.vk.gamma_abc_g1.len(), 
            a_len: self.a_query.len(),
            b_g1_len: self.b_g1_query.len(), 
            b_g2_len: self.b_g2_query.len(), 
            h_len: self.h_query.len(), 
            l_len: self.l_query.len() 
        }
    }
}