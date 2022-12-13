#![cfg_attr(not(feature = "std"), no_std)]
pub use self::versatile_verifier::{VersatileVerifier, VersatileVerifierRef};

use ink_lang as ink;
mod library;

#[ink::contract]
mod versatile_verifier {
    use ink_prelude::{string::String, vec::Vec};

    use substrate_bn::{Fr, Group, G1 as G1Point};

    use crate::library::pairing::{Pairing, Proof, VerifyingKey};
    /// Defines the storage of your contract.
    /// Add new fields to the below struct in order
    /// to add new static storage fields to your contract.
    #[ink(storage)]
    pub struct VersatileVerifier {
        alpha1: Vec<String>,
        beta2: Vec<Vec<String>>,
        gamma2: Vec<Vec<String>>,
        delta2: Vec<Vec<String>>,
        ic: Vec<Vec<String>>,
    }

    impl VersatileVerifier {
        /// Constructor that initializes the `bool` value to the given `init_value`.
        #[ink(constructor)]
        pub fn new(
            alpha1: Vec<String>,
            beta2: Vec<Vec<String>>,
            gamma2: Vec<Vec<String>>,
            delta2: Vec<Vec<String>>,
            ic: Vec<Vec<String>>,
        ) -> Self {
            Self {
                alpha1,
                beta2,
                gamma2,
                delta2,
                ic,
            }
        }

        fn verifying_key(&self) -> VerifyingKey {
            //     VerifyingKey{alpha1: Pairing::slice_to_g1point("19546474065062811480934750932324761960328425995057443442951846622755096807549","6722645273586431204046513586046831552590292032969652170082729975180192742691"),
            // beta2 : Pairing::slice_to_g2point(["19880658973888877860169244078905727037468368485234088774573285060031615049867", "5342742034565472943840576678292999120313759288049292600085237953155293265312"], ["9029238229418247682657957153881099166452077711714796395013060315851112816247", "10985632196680601749057825417366905505985588145856965021675924916242074707186"]),
            // gamma2 : Pairing::slice_to_g2point(["6784380429573154140736156321194855523142094870143858094303508787972024556919", "15144747984057279718554400182071922339774353997477769083933853739326933403989"], ["1576705122432327432730505271150906614082814302464869501424983883452900326617", "9421655938900355160049531052024094357013258938718438607894576986535814846957"]),
            // delta2 : Pairing::slice_to_g2point(["6909973215548258408512842575328726391181103094971646403431995739490180318968", "9597929549945381977453131261282257716303681361764817336160020810173571581615"], ["20408912936105879039083515942141106269482319390995359193693264813039381673106", "943622217811002747106881443767091507581275665578387498586297310420393402581"]),
            // ic:vec![ Pairing::slice_to_g1point("10872056184294966129572845751429689766509211921186846763201899083789946691574","17556855979894237883643452734684091286323987389196496935543342115193721447267"),
            // Pairing::slice_to_g1point("18318578551791216015555734347561649922721034119330693244598390607535206215621","20049465437616992997155012932567235742353967894923277224847581253212648200399"),
            // Pairing::slice_to_g1point("10631105806399311290838904011537828185485877440220088903887029883329971326981","11729647376127193428263792750715836375249892212676547572029021436858221221867"),
            // Pairing::slice_to_g1point("5660394473274246636477471641390753410225877381376207325240317811187402608501","6653234285558675727122651351781675751289692909167724571784718709398565453942"),
            // Pairing::slice_to_g1point("8489326575081913103315440414191657316791709837996796678053534181388344531774","11344790868457396388355317247800319849685201880119103714156644769886518468498"),
            // Pairing::slice_to_g1point("656848943730218389363702383625900878000183222495659570347811011870451279679","18970093947059267687258804934299495158106271056727254104792496985094741180445"),
            // Pairing::slice_to_g1point("9823425797926647725019744075860875914687783192260155407793371477831905865557","3526136121460352789215006981834302696735274480111269454165309887894933487974"),
            // Pairing::slice_to_g1point("20212927611533398057351512990439346098251662391832968161416317616353118756369","560500040140497711759624843565742207372986930335794503712666665029295077243"),
            // Pairing::slice_to_g1point("17489122539421427831760918244551479423343411569400940182976264130884002855796","3485361990223201540341354470425752387961205783523497004516976532592855891365"),
            // Pairing::slice_to_g1point("20592001038968958907106701307507662054416831322308157964690884580393198081070","8987746408793807546336040135843159736803727164404975599197216229763992111670"),
            // Pairing::slice_to_g1point("12703772126761415599778682807193024767330564927042724342862765616718558632376","59821747428616632439950016174962984425359380981033286100759588829505306885"),
            // ]}
            VerifyingKey {
                alpha1: Pairing::vec_to_g1point(&self.alpha1),
                beta2: Pairing::vec_to_g2point(&self.beta2),
                gamma2: Pairing::vec_to_g2point(&self.gamma2),
                delta2: Pairing::vec_to_g2point(&self.delta2),
                ic: self.ic.iter().map(|x| Pairing::vec_to_g1point(x)).collect(),
            }
        }

        /*
         * @returns Whether the proof is valid given the hardcoded verifying key
         *          above and the public inputs
         */
        #[ink(message)]
        pub fn verify_proof(
            &self,
            a: Vec<String>,
            b: Vec<Vec<String>>,
            c: Vec<String>,
            input: Vec<String>,
        ) -> bool {
            let proof = Proof {
                a: Pairing::vec_to_g1point(&a),
                b: Pairing::vec_to_g2point(&b),
                c: Pairing::vec_to_g1point(&c),
            };

            let vk = self.verifying_key();

            // Compute the linear combination vk_x
            let mut vk_x = G1Point::zero();

            // Make sure that proof.a, b, and c are each less than the prime q
            assert!(
                proof.a.x().into_u256() < Pairing::prime_q(),
                "verifier-aX-gte-prime-q"
            );
            assert!(
                proof.a.y().into_u256() < Pairing::prime_q(),
                "verifier-aY-gte-prime-q"
            );

            assert!(
                proof.b.x().real().into_u256() < Pairing::prime_q(),
                "verifier-bX0-gte-prime-q"
            );
            assert!(
                proof.b.y().real().into_u256() < Pairing::prime_q(),
                "verifier-bY0-gte-prime-q"
            );

            assert!(
                proof.b.x().imaginary().into_u256() < Pairing::prime_q(),
                "verifier-bX1-gte-prime-q"
            );
            assert!(
                proof.b.y().imaginary().into_u256() < Pairing::prime_q(),
                "verifier-bY1-gte-prime-q"
            );

            assert!(
                proof.c.x().into_u256() < Pairing::prime_q(),
                "verifier-cX-gte-prime-q"
            );
            assert!(
                proof.c.y().into_u256() < Pairing::prime_q(),
                "verifier-cY-gte-prime-q"
            );

            // Make sure that every input is less than the snark scalar field
            //for (uint256 i = 0; i < input.length; i++) {
            for i in 0..10 {
                assert!(
                    Fr::from_str(&input[i]).unwrap().into_u256() < Pairing::snark_scalar_field(),
                    "verifier-gte-snark-scalar-field"
                );
                vk_x = Pairing::plus(
                    vk_x,
                    Pairing::scalar_mul(vk.ic[i + 1], Fr::from_str(&input[i]).unwrap()),
                );
            }

            vk_x = Pairing::plus(vk_x, vk.ic[0]);

            Pairing::pairing(&[
                (Pairing::negate(proof.a), proof.b),
                (vk.alpha1, vk.beta2),
                (vk_x, vk.gamma2),
                (proof.c, vk.delta2),
            ])
        }
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;

        /// We test if the default constructor does its job.
        #[ink::test]
        fn default_works() {}

        /// We test a simple use case of our contract.
        #[ink::test]
        fn it_works() {}
    }
}
