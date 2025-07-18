// Arion Hash (RescuePrime-like modular structure, struct-based)
use crate::modulus::{FieldElement, Field};

pub mod params {
    use super::*;

    #[derive(Clone)]
    pub struct ArionGTDSParams {
        pub d1: u128,
        pub e: u128,
        pub alpha1: Vec<FieldElement>,
        pub alpha2: Vec<FieldElement>,
        pub beta: Vec<FieldElement>,
    }

    #[derive(Clone)]
    pub struct ArionParams {
        pub field: Field,
        pub gtds_params: ArionGTDSParams,
        pub mds_matrix: Vec<Vec<FieldElement>>,
        pub round_constants: Vec<Vec<FieldElement>>,
        pub rate: usize,
        pub capacity: usize,
        pub rounds: usize,
    }
}

pub struct ArionHasher {
    pub params: params::ArionParams,
}

impl ArionHasher {
    pub fn new(params: params::ArionParams) -> Self {
        Self { params }
    }

    fn apply_gtds(&self, x: &[FieldElement]) -> Vec<FieldElement> {
        let field = &self.params.field;
        let n = x.len();
        let mut f = vec![field.zero(); n];
        let gtds = &self.params.gtds_params;

        f[n - 1] = x[n - 1].pow(gtds.e);

        for i in (0..n - 1).rev() {
            let mut sigma = self.params.field.zero();
            for j in i + 1..n {
                sigma = &sigma + &x[j];
                sigma = &sigma + &f[j];
            }
            let g = &(sigma^2) + &(&(&gtds.alpha1[i] * &sigma) + &gtds.alpha2[i]);
            let h = &(sigma^2) + &(&gtds.beta[i] * &sigma);
        f[i] = &x[i].pow(gtds.d1) * &(&g + &h);
        }
        f
    }

    fn apply_mds(&self, state: &[FieldElement]) -> Vec<FieldElement> {
        let field = &self.params.field;
        let mut result = Vec::with_capacity(state.len());
        for row in &self.params.mds_matrix {
            let mut acc = field.zero();
            for (m, s) in row.iter().zip(state) {
                acc = &acc + &(m * s);
            }
            result.push(acc);
        }
        result
    }

    fn permutation(&self, state: &[FieldElement]) -> Vec<FieldElement> {
        let mut state = state.to_vec();

        for r in 0..self.params.rounds {
            state = self.apply_gtds(&state);
            state = self.apply_mds(&state);
            for (s, c) in state.iter_mut().zip(&self.params.round_constants[r]) {
                *s = &*s + c;
            }
        }

        state
    }

    pub fn hash(&self, input: &[FieldElement]) -> Vec<FieldElement> {
        let field = &self.params.field;
        let mut state = vec![field.zero(); self.params.rate + self.params.capacity];

        for chunk in input.chunks(self.params.rate) {
            for (i, val) in chunk.iter().enumerate() {
                state[i] = &state[i] + val;
            }
            state = self.permutation(&state);
        }

        state[..self.params.rate].to_vec()
    }
    pub fn generate_trace(&self, input: &[FieldElement]) -> Vec<Vec<FieldElement>> {
        let field = &self.params.field;
        let mut trace = Vec::new();
        let mut state = vec![field.zero(); self.params.rate + self.params.capacity];

        for chunk in input.chunks(self.params.rate) {
            for (i, val) in chunk.iter().enumerate() {
                state[i] = &state[i] + val;
            }
            for r in 0..self.params.rounds {
                trace.push(state.clone());
                state = self.apply_gtds(&state);
                state = self.apply_mds(&state);
                for (s, c) in state.iter_mut().zip(&self.params.round_constants[r]) {
                    *s = FieldElement::from(&*s + &*c);
                }
            }
        }

        trace
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modulus::{FieldElement, Field};
    
    fn dummy_params(n: usize, rounds: usize) -> params::ArionParams {
        let field = Field{p: 340282366920938463463374557953744961537}; // (1 << 128) - 45 * (1 << 40) + 1
        let dummy_vec = vec![field.one(); n];
        let mds  = vec![
            vec![
                FieldElement{value: 340282366920938463463374557953730612630, field},
                FieldElement{value: 21493836, field},
                FieldElement{value: 340282366920938463463374557953736934518, field},
                FieldElement{value: 914760, field},
                FieldElement{value: 340282366920938463463374557953744928504, field},
                FieldElement{value: 364, field}
            ],
            vec![
                FieldElement{value: 340282366920938463463374557948521959389, field},
                FieldElement{value: 7809407397, field},
                FieldElement{value: 340282366920938463463374557950844620457, field},
                FieldElement{value: 324945621, field},
                FieldElement{value: 340282366920938463463374557953733852285, field},
                FieldElement{value: 99463, field}
            ],
            vec![
                FieldElement{value: 340282366920938463463374556526559624596, field},
                FieldElement{value: 2132618407920, field},
                FieldElement{value: 340282366920938463463374557163162978137, field},
                FieldElement{value: 88084432800, field},
                FieldElement{value: 340282366920938463463374557950784345879, field},
                FieldElement{value: 25095280, field}
            ],
            vec![
                FieldElement{value: 340282366920938463463374197863906102577, field},
                FieldElement{value: 537966647357139, field},
                FieldElement{value: 340282366920938463463374358646073999137, field},
                FieldElement{value: 22165576349400, field},
                FieldElement{value: 340282366920938463463374557212857010097, field},
                FieldElement{value: 6174066262, field}
            ],
            vec![
                FieldElement{value: 340282366920938463463285966851139685903, field},
                FieldElement{value: 132344277849702072, field},
                FieldElement{value: 340282366920938463463325536573199985698, field},
                FieldElement{value: 5448481182864720, field},
                FieldElement{value: 340282366920938463463374376171390478291, field},
                FieldElement{value: 1506472167928, field}
            ],
            vec![
                FieldElement{value: 340282366920938463441758328918057706841, field},
                FieldElement{value: 32291274613403616174, field},
                FieldElement{value: 340282366920938463451414421516665416977, field},
                FieldElement{value: 1329039099788841441, field},
                FieldElement{value: 340282366920938463463330243139804660633, field},
                FieldElement{value: 366573514642546, field}
            ]
        ];
        let rc = vec![
            FieldElement{value: 283083741260354679619488780134497021322, field},
            FieldElement { value: 38254929096665236039757969044807818294, field },
            FieldElement { value: 307965684402143955779927159218259701765, field },
            FieldElement { value: 120452194550780187668810020520948697472,  field },
            FieldElement { value: 255392762847339380279017258791724911843,  field },
            FieldElement { value: 104396165105789949249045594620940452128,  field },
            FieldElement { value: 209554308574842985514728462938022424547,  field },
            FieldElement { value: 277234278182354871096282801945400879072,  field },
            FieldElement { value: 102339713892641645259311534863727943407,  field },
            FieldElement { value: 6550832216417370121282126485935606608,  field },
            FieldElement { value: 274264920704079577628626333702358976636,  field },
            FieldElement { value: 141167056886880822545991258824346333002,  field },
            FieldElement { value: 192450021488800140247962444459040725958,  field },
            FieldElement { value: 236212188898688196919821276131506030663,  field },
            FieldElement { value: 95471267584340394858490726809263637774,  field },
            FieldElement { value: 198533335283291721371918676351641306089,  field },
            FieldElement { value: 150980653911865026783858931554333375653,  field },
            FieldElement { value: 93951994606999957857425594205226763116,  field },
            FieldElement { value: 126186848264243618547358201502880508344,  field },
            FieldElement { value: 148525132745758303896449520806665309699,  field },
            FieldElement { value: 321087144004680644738362829069136941406,  field },
            FieldElement { value: 313722747735750413186713305602906413066,  field },
            FieldElement { value: 199797786735540296630011326567046940336,  field },
            FieldElement { value: 276170382703831712879641961404498360532,  field },
            FieldElement { value: 28974494109565361900445506140676821550,  field },
            FieldElement { value: 57353412412175508294106865995769137969,  field },
            FieldElement { value: 132254575408604750773909972145851982849,  field },
            FieldElement { value: 144941802086669228041745410404034708463,  field },
            FieldElement { value: 21514361970409156108408545459263025896,  field },
            FieldElement { value: 154716217827328508828232462283612685331,  field },
            FieldElement { value: 206169210322910481779409259772219267328,  field },
            FieldElement { value: 142291415492687874419349827221860312986,  field },
            FieldElement { value: 204159844269886262030341950659047754237,  field },
            FieldElement { value: 162054793125944167631111386250624148852,  field },
            FieldElement { value: 117507260664398289416565455968301959407,  field },
            FieldElement { value: 229438301587329686577631441228154147759,  field },
            FieldElement { value: 6791258128237248344780324021385666548,  field },
            FieldElement { value: 179238009540773382389029763349833863202,  field },
            FieldElement { value: 252517915748009168057897949890471694268,  field },
            FieldElement { value: 78561070598375533378721143848221548936,  field },
            FieldElement { value: 196834177295821480825634715760850368598,  field },
            FieldElement { value: 321040260510665931473035421891191935384,  field },
            FieldElement { value: 337823013260556962133927177323846616548,  field },
            FieldElement { value: 263532469585890559505027462053623207546,  field },
            FieldElement { value: 80772170951719266169315255151519967764,  field },
            FieldElement { value: 191126238705133634714627266914793518474,  field },
            FieldElement { value: 168640980462606148671409979847472750720,  field },
            FieldElement { value: 311392606137894925254540397823868318693,  field },
            FieldElement { value: 53033415319989015392420379491726296169,  field },
            FieldElement { value: 334667992555281204199891768112724382888,  field },
            FieldElement { value: 239338818416107619824098885800420242124,  field },
            FieldElement { value: 336233115919022329244085455907862244031,  field },
            FieldElement { value: 17689913696084027970400238776249520788,  field },
            FieldElement { value: 35962141184832629375539702334312095071,  field },
            FieldElement { value: 63261929061469329267964507628940776575,  field },
            FieldElement { value: 229052631211585585812981356178908453275,  field },
            FieldElement { value: 18904163736232594988753899237611053770,  field },
            FieldElement { value: 337975656091270016865226704912024570639,  field },
            FieldElement { value: 112662217991923651732332934890007730052,  field },
            FieldElement { value: 272075142017584623851838463289412220042,  field },
            FieldElement { value: 209734195747531667384105457096639826986,  field },
            FieldElement { value: 323517349607435165658386033341669683280,  field },
            FieldElement { value: 162744127160813542902932186627498059818,  field },
            FieldElement { value: 337052554017898596492087589159602397000,  field },
            FieldElement { value: 136808487593378113778645329916568118488,  field },
            FieldElement { value: 278698115731566901915478028147688843175,  field },
            FieldElement { value: 650080734541862191861276870712408389,  field },
            FieldElement { value: 2992760983747874297668265306928897114,  field },
            FieldElement { value: 127633014458454841979037550565605502705,  field },
            FieldElement { value: 130731350002924669843034805716072251680,  field },
            FieldElement { value: 102520882387446974238428337703875846986,  field },
            FieldElement { value: 71084280894741056133539286928819366512,  field },
            FieldElement { value: 266527169034593814284471903859999788151,  field },
            FieldElement { value: 290210609215304682905231303632582321277,  field },
            FieldElement { value: 100979170766572525148751249524131510013,  field },
            FieldElement { value: 297000580095973144414375575909606534223,  field },
            FieldElement { value: 268556839276489696990016507773947777274,  field },
            FieldElement { value: 215674342949958281691243239315022785973,  field },
            FieldElement { value: 180388968526392763107310038113997462800,  field },
            FieldElement { value: 331402333105596911086765331575600687941,  field },
            FieldElement { value: 148623446178856289901428241450695721921,  field },
            FieldElement { value: 316244534879571616552738095268429404043,  field },
            FieldElement { value: 190548966399889334891592309816567520821,  field },
            FieldElement { value: 21110543454063464927222597454866812677,  field },
            ];
        let rc = vec![dummy_vec.clone(); rounds];
        params::ArionParams {
            field: field, //(1 << 128) - 45 * (1 << 40) + 1;
            gtds_params: params::ArionGTDSParams {
                d1: 5,
                e: 103,
                alpha1: dummy_vec.clone(),
                alpha2: dummy_vec.clone(),
                beta: dummy_vec,
            },
            mds_matrix: mds,
            round_constants: rc,
            rate: n - 2,
            capacity: 2,
            rounds,
        }
    }
    #[test]
    fn test_arion_hash_basic() {
        let params = dummy_params(6, 5);
        let hasher = ArionHasher::new(params.clone());
        let field = params.field;
        let input = 
            vec![FieldElement::new(3, field), FieldElement::new(5, field), FieldElement::new(7, field), FieldElement::new(1, field)];
        let output = hasher.hash(&input);
        assert_eq!(output.len(), params.rate);
    }
    #[test]
    fn test_arion_trace_generation() {
        let params = dummy_params(6, 5);
        let hasher = ArionHasher::new(params.clone());
        let field = params.field;
        let input = 
            vec![FieldElement::new(3, field), FieldElement::new(5, field), FieldElement::new(7, field), FieldElement::new(1, field)];
        let trace = hasher.generate_trace(&input);
        // 1 chunk × 5 rounds = 5 trace steps
        assert_eq!(trace.len(), 5);
        assert_eq!(trace[0].len(), params.rate + params.capacity);
    }
}
