use crate::modulus;
use modulus::modulus::Field as Field;
use modulus::modulus::FieldElement as FieldElement;

pub mod rescueprime{
    use crate::modulus;
    use modulus::modulus::Field as Field;
    use modulus::modulus::FieldElement as FieldElement;

    pub struct RescuePrime {
        pub p: u128,
        pub field: Field,
        m: usize,
        N: usize,
        alpha: u128,
        alphainv: u128,
        pub MDS: Vec<Vec<FieldElement>>,
        pub MDSinv: Vec<Vec<FieldElement>>,
        pub round_constants: Vec<FieldElement>,
    }

    impl RescuePrime {
        pub fn new() -> Self {
            let p = 340282366920938463463374557953744961537; //(1 << 128) - 45 * (1 << 40) + 1;
            let field = Field { p: p };
            let alpha = 5;
            let alphainv = 272225893536750770770699646362995969229;
            let m = 6;
            let N = 7;

            let MDS = vec![
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

            let MDSinv = vec![
                vec![
                    FieldElement{value: 133202720344903784697302507504318451498, field},
                    FieldElement{value: 9109562341901685402869515497167051415, field},
                    FieldElement{value: 187114562320006661061623258692072377978, field},
                    FieldElement{value: 217977550980311337650875125151512141987, field},
                    FieldElement{value: 274535269264332978809051716514493438195, field},
                    FieldElement{value: 198907435511358942768401550501671423539, field}
                ],
                vec![
                    FieldElement{value: 107211340690419935719675873160429442610, field},
                    FieldElement{value: 93035459208639798096019355873148696692, field},
                    FieldElement{value: 34612840942819361370119536876515785819, field},
                    FieldElement{value: 28124271099756519590702162721340502811, field},
                    FieldElement{value: 220883180661145883341796932300840696133, field},
                    FieldElement{value: 196697641239095428808435254975214799010, field}
    
                ],
                vec![
                    FieldElement{value: 48198755643822249649260269442324041679, field},
                    FieldElement{value: 64419499747985404280993270855996080557, field},
                    FieldElement{value: 280207800449835933431237404716657540948, field},
                    FieldElement{value: 61755931245950637038951462642746253929, field},
                    FieldElement{value: 206737575380416523686108693210925354496, field},
                    FieldElement{value: 19245171373866178840198015038840651466, field}  
                ],
                vec![
                    FieldElement{value: 133290479635000282395391929030461304726, field},
                    FieldElement{value: 256035933367497105928763702353648605000, field},
                    FieldElement{value: 97077987470620839632334052346344687963, field},
                    FieldElement{value: 144638736603246051821344039641662500876, field},
                    FieldElement{value: 323753713558453221824969500168839490204, field},
                    FieldElement{value: 66050250127997888787320450320278295843, field}
                ],
                vec![
                    FieldElement{value: 107416947271017171483976049725783774207, field},
                    FieldElement{value: 29799978553141132526384006297614595309, field},
                    FieldElement{value: 112991183841517485419461727429810868869, field},
                    FieldElement{value: 27096959906733835564333321118624482460, field},
                    FieldElement{value: 197262955506413467422574209301409294301, field},
                    FieldElement{value: 205996708763053834510019802034246907929, field}
                ],
                vec![
                    FieldElement{value: 114827794598835201662537916675749328586, field},
                    FieldElement{value: 22232541983454090535685600849896663137, field},
                    FieldElement{value: 84718265936029339288536427868493390350, field},
                    FieldElement{value: 176534200716138685131361645691447579493, field},
                    FieldElement{value: 304590074876810806644622682832255680729, field},
                    FieldElement{value: 317944222651547267127379399943392242317, field}
                ],
            ];

            let round_constants = vec![
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

            RescuePrime {
                p,
                field,
                m,
                N,
                alpha,
                alphainv,
                MDS,
                MDSinv,
                round_constants,
            }
        }

        pub fn hash(&self, mut input_element: Vec<FieldElement>) -> Vec<FieldElement> {
            // イテレータ→ベクター
            input_element.extend(vec![FieldElement{value: 0, field: self.field}; self.m - input_element.len()]);
            let mut state = input_element;

            for r in 0..self.N {
                // forward half-round
                for i in 0..self.m {
                    state[i] = state[i] ^ (self.alpha);
                }

                let mut temp = vec![FieldElement{value: 0, field: self.field}; self.m];
                for i in 0..self.m {
                    for j in 0..self.m {
                        temp[i] = temp[i] + self.MDS[i][j] * state[j];
                    }
                }

                for i in 0..self.m {
                    state[i] = temp[i] + self.round_constants[2 * r * self.m + i];
                }

                // backward half-round
                for i in 0..self.m {
                    state[i] = state[i] ^ self.alphainv;
                }

                let mut temp = vec![FieldElement{value: 0, field: self.field}; self.m];
                for i in 0..self.m {
                    for j in 0..self.m {
                        temp[i] = temp[i] + self.MDS[i][j] * state[j];
                    }
                }

                for i in 0..self.m {
                    state[i] = temp[i] + self.round_constants[2 * r * self.m + self.m + i];
                }
            }

            vec![state[0].clone(), state[1].clone()]
        }
    }
}
fn main() {
    println!("Hash");
}