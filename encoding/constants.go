package encoding

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const BYTES_PER_COEFFICIENT = 32

const NUMBER_FR_SECURITY_BYTES = 32

func init() {
	initGlobals()
}

func ToFr(v string) fr.Element {
	var out fr.Element
	_, err := out.SetString(v)
	if err != nil {
		fmt.Println("Failed to initialize Root of Unity")
		panic(err)
	}
	return out
}

var Scale2RootOfUnity []fr.Element
var ZERO, ONE, TWO fr.Element
var MODULUS_MINUS1, MODULUS_MINUS1_DIV2, MODULUS_MINUS2 fr.Element
var INVERSE_TWO fr.Element

// copied from https://github.com/adjoint-io/pairing/blob/master/src/Data/Pairing/BN254.hs
func initGlobals() {
	Scale2RootOfUnity = []fr.Element{
		ToFr("1"),
		ToFr("21888242871839275222246405745257275088548364400416034343698204186575808495616"),
		ToFr("21888242871839275217838484774961031246007050428528088939761107053157389710902"),
		ToFr("19540430494807482326159819597004422086093766032135589407132600596362845576832"),
		ToFr("14940766826517323942636479241147756311199852622225275649687664389641784935947"),
		ToFr("4419234939496763621076330863786513495701855246241724391626358375488475697872"),
		ToFr("9088801421649573101014283686030284801466796108869023335878462724291607593530"),
		ToFr("10359452186428527605436343203440067497552205259388878191021578220384701716497"),
		ToFr("3478517300119284901893091970156912948790432420133812234316178878452092729974"),
		ToFr("6837567842312086091520287814181175430087169027974246751610506942214842701774"),
		ToFr("3161067157621608152362653341354432744960400845131437947728257924963983317266"),
		ToFr("1120550406532664055539694724667294622065367841900378087843176726913374367458"),
		ToFr("4158865282786404163413953114870269622875596290766033564087307867933865333818"),
		ToFr("197302210312744933010843010704445784068657690384188106020011018676818793232"),
		ToFr("20619701001583904760601357484951574588621083236087856586626117568842480512645"),
		ToFr("20402931748843538985151001264530049874871572933694634836567070693966133783803"),
		ToFr("421743594562400382753388642386256516545992082196004333756405989743524594615"),
		ToFr("12650941915662020058015862023665998998969191525479888727406889100124684769509"),
		ToFr("11699596668367776675346610687704220591435078791727316319397053191800576917728"),
		ToFr("15549849457946371566896172786938980432421851627449396898353380550861104573629"),
		ToFr("17220337697351015657950521176323262483320249231368149235373741788599650842711"),
		ToFr("13536764371732269273912573961853310557438878140379554347802702086337840854307"),
		ToFr("12143866164239048021030917283424216263377309185099704096317235600302831912062"),
		ToFr("934650972362265999028062457054462628285482693704334323590406443310927365533"),
		ToFr("5709868443893258075976348696661355716898495876243883251619397131511003808859"),
		ToFr("19200870435978225707111062059747084165650991997241425080699860725083300967194"),
		ToFr("7419588552507395652481651088034484897579724952953562618697845598160172257810"),
		ToFr("2082940218526944230311718225077035922214683169814847712455127909555749686340"),
		ToFr("19103219067921713944291392827692070036145651957329286315305642004821462161904"),
	}

	ZERO.SetZero()
	ONE.SetOne()
	TWO.SetInt64(int64(2))
	MODULUS_MINUS1.Sub(&ZERO, &ONE)
	MODULUS_MINUS1_DIV2.Div(&MODULUS_MINUS1, &TWO)
	MODULUS_MINUS2.Sub(&ZERO, &TWO)
	INVERSE_TWO.Inverse(&TWO)
}
