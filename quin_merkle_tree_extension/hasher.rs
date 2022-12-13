use dusk_bls12_381::BlsScalar;
use hex_literal::hex;
use ink_env::hash::{Blake2x256, CryptoHash, HashOutput};
#[cfg(feature = "std")]
use ink_storage::traits::StorageLayout;
use ink_storage::traits::{PackedLayout, SpreadAllocate, SpreadLayout};

const MAX_DEPTH:usize=32;
#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadAllocate, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, ink_storage::traits::StorageLayout))]
pub struct Blake;

impl MerkleTreeHasher for Blake {
    type Output = <Blake2x256 as HashOutput>::Type;

    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output {
        let mut result = Self::Output::default();

        Blake2x256::hash(&[left, right].concat(), &mut result);
        result
    }
    fn hash5(array: [Self::Output; 5]) -> Self::Output {
        let mut result = Self::Output::default();
        Blake2x256::hash(&(&array).concat(), &mut result);
        result
    }
    ///Array with zero elements(every leaf is blake2x256("slushie")) for a MerkleTree with Blake2x256
    const ZEROS: [Self::Output; MAX_DEPTH] = [
        hex!("DF26FF86CD6E61248972E4587A1676FF2DE793D9D39BA77D8623B3CF98097964"), //=blake2x256("slushie")
        hex!("08A1F07AA709C548AB2FF9E131D592AD5F51AE98A422EB7DD4EC4BB5851224F7"),
        hex!("7FFD603771A2F3081DA519DD801BA92155FE3D0AEE2414F2D5F5A50A85905A9D"),
        hex!("AC6B640D0248376B1853EFF9D6EF755589EDAD57C89B418D2E769F0878714A6A"),
        hex!("3BB8C18776E7262665D755341C34D1BFFF8A47A4CBA32B00587A118C3949C333"),
        hex!("2B56D350CAA77C271671BAC2926C63318C808F826038AE9528061160919CDB66"),
        hex!("F4E29395681B76B9CCB43BBA7A25A6E579AEA997719C45CB67B59BEB29998767"),
        hex!("37DD0B2E55B8DCB8599F6F07A98D664AB65AA7FDE1DC0A10C5C34F6D6B8DDB29"),
        hex!("084A95D2144039C0D30E55AC852123F381AEADE943A67BA407556BF4108A6E28"),
        hex!("4C40869E7648D141C0F566404A7FB7CC5A7ADE25F618BA57E01A7DCF6ACCB4B7"),
        hex!("98EEFD72911C6D53CCD185D4B1112ACC473C09D2629CE54E29802DC51D6E248E"),
        hex!("2D8200DE6D7B7B8713251983CC6607F564C318EF0142CE248F8604B268A03435"),
        hex!("C76DD3166E3CB3C6F5710C7342EF808BECE631107D247041ABDD6E90EFF00093"),
        hex!("548E07F911927EFEA1690308BAE15482146A846DBE3A0615ABEE4D000385FCF1"),
        hex!("59A40D5B3CC23C49E9B39898DA03E93D3FADE7F21CABDB4158DF3A8E16BF2770"),
        hex!("F35EE3968504FBE69D3F3AD50EC462BDF89B4D52FBF20FFCA03A2386A02A6C93"),
        hex!("3BF9B77569D6DADF938D8A8D2655EECEB25A1AEA8CE8A8966BE75089F575814E"),
        hex!("4C085D252A8A74A8D421C02F6D88A0DA09F97A08704BC2211883D66692B2D3F5"),
        hex!("CB9EAC104C0233AC559518A1FF4B6ACC82CDB6898EB96C92E6BD156542817F26"),
        hex!("0D9781719606274A7112738574248DB77549935E07A89F8DEC8AE0D8BF74EEED"),
        hex!("6D55AC6517C59DC452FF2EFB0FAC5EC744E5486D129F3FDEDF675FB8B6E39DB7"),
        hex!("65E5AC035957EB54E4A10A21E80684652221E4C6A3015A0F6FE45FB6E6E12757"),
        hex!("AE33C85AB0D4DDC7371E1E56B7FF988761AD512EA22694387D12758A35F47F1E"),
        hex!("391CA0F22B37FF113E68360BCB7F7642A85A9BC48DD0CDBB295D3AE44BAE08FD"),
        hex!("847F01F4FB6FF5D8CE6C1984ECC08D4B9C3240AE780A60C893FEAC4220C55598"),
        hex!("DC390096531C2B643AB506EFC0BB8470DF74B25BCA24CAF36CC7DF73AE4FDE19"),
        hex!("38BC78A550172C2274C562422790D9F326CE3EB5998C0A1CB2C4455147970BA7"),
        hex!("419772135A10641AAFE5570CBC804FC76C0828D37B25663A0112BD5D049E15F6"),
        hex!("719340CC69722407872C2B19BE3504703EF1C78DB8EA17725957894A2E956441"),
        hex!("9B8D1843441D8974232866695C62672CBCE4ABA28073A33747B146E2DECA13EB"),
        hex!("FBF8667A0CECF72A92D07A4E5F26C13BB4555F4454E6BD1EBE9FB7F661C6C427"),
        hex!("C1868E018222455A946E804B70C9929AFBAE56A2CAB9F7722EDCF26039CFA0FE"),
    ];
}

#[derive(scale::Encode, scale::Decode, PackedLayout, SpreadAllocate, SpreadLayout, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug, ink_storage::traits::StorageLayout))]
pub struct Poseidon;

impl Poseidon {
    pub fn bytes_to_scalar(bytes: [u8; 32]) -> BlsScalar {
        BlsScalar(Self::bytes_to_u64(bytes))
    }

    pub fn scalar_to_bytes(scalar: BlsScalar) -> [u8; 32] {
        Self::u64_to_bytes(*scalar.internal_repr())
    }

    pub fn bytes_to_u64(bytes: [u8; 32]) -> [u64; 4] {
        let mut result = [0; 4];

        for i in 0..result.len() {
            let bytes_8 = bytes.split_at(i * 8).1.split_at(8).0;
            let bytes_array = <&[u8; 8]>::try_from(bytes_8).unwrap();
            result[i] = u64::from_be_bytes(*bytes_array);
        }

        result
    }

    pub fn u64_to_bytes(array: [u64; 4]) -> [u8; 32] {
        let mut result = [0; 32];

        for i in 0..array.len() {
            let bytes_array = array[i].to_be_bytes();
            for j in 0..bytes_array.len() {
                result[i * 8 + j] = bytes_array[j];
            }
        }

        result
    }
}

impl MerkleTreeHasher for Poseidon {
    type Output = [u8; 32];

    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output {
        let left = Self::bytes_to_scalar(left);
        let right = Self::bytes_to_scalar(right);
        let result = dusk_poseidon::sponge::hash(&[left, right]);

        Self::scalar_to_bytes(result)
    }
    fn hash5(array: [Self::Output; 5]) -> Self::Output {
        let array: ink_prelude::vec::Vec<BlsScalar> = array
            .into_iter()
            .map(|a| Self::bytes_to_scalar(a))
            .collect();
        let result = dusk_poseidon::sponge::hash(&array);

        Self::scalar_to_bytes(result)
    }
    ///Array with zero elements(every leaf is scalar::from(blake2x256("slushie"))) for a MerkleTree with Poseidon
    const ZEROS: [Self::Output; MAX_DEPTH] = [
        hex!("21022C8B84947BF9FB67A7EB96CC2240F9DB61466F91697B5139DC623AF1DE85"), //=scalar::from(blake2x256("slushie"))
hex!("087343DF8DC70C298C0CF90E075DB0CDEF2B94F2E9248DC56EFCA4D5F94EA102"),
hex!("A8D1890D4207CE7FF31A6FF5B5CE4556287402CC14734AA459AB4240B4CC0661"),
hex!("BFA78900EE3A61F26001A1BC10332689240B5B0229A2B60411366C48035019DC"),
hex!("1DC88B872E0DD8DD76A22946D12113A1A3012B706666AA6C3D2D73D5D3686BB7"),
hex!("FA1B2D41DDB55A5450AA47AB2FCC672D43C99171FDB2932468B99C89FB9A1CB0"),
hex!("F2B9084692AAEB8944050463A80896306AE3AD4D4E808667249ACF40595A9E21"),
hex!("D61267DA347E7199025D22F30CCE0076F7FB49F3DFFBB99E50952AC037BB0D8B"),
hex!("5FC09AD61149F4619ED701FC62D84A4AAD16ACD87CAB3A864A11252991ADA503"),
hex!("47EEE035C49744E32715FDF289D92E65F0D21889839BAB2851EA94A1031369B2"),
hex!("70D7E0011211A9DC4D2B8121A083DB0354B62A6F46A9695549099EFF6FDC4C3E"),
hex!("E924A8024BF18B9491927C789AD38F3AB974D11C26CDA4AD6F068A4FE3EE306D"),
hex!("03B2A1F22E45385C5F3C4562880F2A6F9C0BD38210B9759D5B8B8068A069395C"),
hex!("AC98F3A9392186F52F310FE96D56A18A3ACDD1DFE68B5FE54AA14BB058C398EE"),
hex!("3AB2FF49556EA31DA33EC396F4DE67C2919DBC780076E8421473F91A2AAE094B"),
hex!("D950F86982D82A5CB6D1DC64EF1FD365F79203B51D047C8011C216BE5137DBC4"),
hex!("5B99C8AA8D207224B6E1D3FD80B5979ACD5F5F16E5754B2A14D936AFBDD2D98E"),
hex!("316D1812277B41B2F1BB52851AE9ECB4D7E710639B8B4E364C31B715A3034B43"),
hex!("5370896B1A799E7673694B587646B7120F1337C544C03EE73A137F4A5B0AC3BF"),
hex!("0C6C5CEE755B8F6DAC98CC9B05D505C5753EF8989216C23F231DBBB961042727"),
hex!("C1E43E5CC46698D341DBB31AE61AAADA0C259A63D269FE213EA05A45D8DC55EC"),
hex!("8C0CC255D6B272F06D7C0B3A9FF86BD2C6F65A94048B42DE662ED3CAF41BD8E2"),
hex!("C1E6F612A401630A01F8A22D5B6B803954E046B022E351EE5EA60788250F3E7A"),
hex!("08FF54BB56BCE1B9008DA3F78A2F70D58B0DA65A534AF5A008627A9BB05420A3"),
hex!("E23B495A62C4DA633EC548ED5C709562A6C2F647F364D3BA191ECBD08C1ABD15"),
hex!("1500439DD502B02031D0DE97697FE09C03A9D949ECE6F52233636BE610F24E1F"),
hex!("3CACFE816B5F914294154BB2EE3DE6A040249580AAD9C3BE484505CA9069A900"),
hex!("06A1022FA71C8960CF710D826E58C525D5682FB0EEF07B8031550BF3DB7701C0"),
hex!("F7E67357D4C77D9B8D60C541CD88E7B65A53BE394F75172510394D5B7A26FA9D"),
hex!("7AE4A186AB31E223FCB65402BDE72E6DC4738C73B539B81160C86EE7D5432616"),
hex!("5B8632ADE822DB881F4EA7F2901681DEA1F99E012EF2DB35023182842F087D66"),
hex!("8B40F1BB45A1A167EB781F548D1530C343CEDEC84D0FAE2071FE68BBE68ADA4D"),
    ];
}

///Trait which require implementation hash for subtrees, MAX_DEPTH zero elements, and hash output
#[cfg(feature = "std")]
pub trait MerkleTreeHasher:
    scale::Encode + scale::Decode + PackedLayout + SpreadAllocate + SpreadLayout + StorageLayout
{
    type Output: 'static
        + scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadAllocate
        + SpreadLayout
        + StorageLayout
        + scale_info::TypeInfo
        + Clone
        + Copy
        + PartialEq
        + Default;

    ///Array with zero elements for a MerkleTree
    const ZEROS: [Self::Output; MAX_DEPTH];

    /// Calculate hash for provided left and right subtrees
    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output;
    fn hash5(array: [Self::Output; 5]) -> Self::Output;
}

///Trait which require implementation hash for subtrees, MAX_DEPTH zero elements, and hash output
#[cfg(not(feature = "std"))]
pub trait MerkleTreeHasher:
    scale::Encode + scale::Decode + PackedLayout + SpreadAllocate + SpreadLayout
{
    type Output: scale::Encode
        + scale::Decode
        + PackedLayout
        + SpreadAllocate
        + SpreadLayout
        + Clone
        + Copy
        + PartialEq
        + Default;

    ///Array with zero elements for a MerkleTree
    const ZEROS: [Self::Output; MAX_DEPTH];
    /// Calculate hash for provided left and right subtrees
    fn hash_left_right(left: Self::Output, right: Self::Output) -> Self::Output;
    fn hash5(array: [Self::Output; 5]) -> Self::Output;
}
