//!

pub mod aarch64;
pub mod traits;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(target_arch = "aarch64")]
pub type GarbEngine = aarch64::Aarch64GarblingInstance;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
