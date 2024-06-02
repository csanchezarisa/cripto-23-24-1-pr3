#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest

from P2024_Practica3_Skeleton import *


dsa_pubkey_1 = [12146861696778682560208895762577538340855284245968018862468655164945848696334937243289414784615027154914133336619765275830398901448953185610916219035058177, 1073794090208220036508630124084389207589842043437, 1105177537547455979482529557768196155224614678915812245018597160809402728002566548625514022632001233703146051901684331712893515701150850628114722339072753, 9183415521443610216209563158463915356468789391014058230646722921228933445199912593530197674578485462449803908903698989620183954199128820330861008902371469]

dsa_pubkey_2 = [8468861956751219485016264539211616189568370975628310939344364504345244682837557817889276808157372443382172002505161085055111292605100715595690500530634753, 1231002442619199850850954999684957172857654858033, 4463865485829126741233166967415576671725947782992796180948186649720136792182543147466944494259541720578289550854365275114704079568630150499881889559926866, 5561884945327004786531439829554599743796365433467234248951857856174221385775318687394489393541000687325549661911611882642068573528040812957660141477026091]

dsa_pubkey_3 = [12122914916503915981493331697831656906598439099956613231619499825076819392053339480682174535068942616410128523518561014438220989426532536184709302062153729, 1365236137057936060547479689969844358236073179789, 5409959414576604564354491561565816526662671628489321649187599320709856256698474402817516457006614129145252031093960441840963862512910495832193484250073016, 1323926773737628817838933726940606725559632289676898922251239840857405159217376853301816918914845123523543844637756168252458671508635957405094989445753251]

dsa_pubkey_4 = [96949358576273823073152005252746995262982363260686509074652822575680588923822624874266636599791830025283695282049455150569626661293221531976918737163223241540816091623537189222462279437538278460918513738981331831586536459725851992038851286525335839858129809544074626106804442703877804053769918392976297533041, 1351224274196029729175941030223930922630679554539, 37963715387860880485367544851679263368614944518017770553633176798443137867734989077750022515175202073478109643140499945929540655913036040429856040547350201210110762349430643045046234078839149491942329381864843107866701723407607741974711033593684694694169406410430554656560071416137693022833889306885688878041, 24410854803584330165803904243929921620858573279828982681525032363017500157563550205351135420699969280430576579712532903516637923080976804550712266263438801464577989140573850705574729320566627113331845294981288403340168671076357846551443763236690253742731919586916176756974881869785922829156767508009802000955]
dsa_privkey_4 = [96949358576273823073152005252746995262982363260686509074652822575680588923822624874266636599791830025283695282049455150569626661293221531976918737163223241540816091623537189222462279437538278460918513738981331831586536459725851992038851286525335839858129809544074626106804442703877804053769918392976297533041, 1351224274196029729175941030223930922630679554539, 37963715387860880485367544851679263368614944518017770553633176798443137867734989077750022515175202073478109643140499945929540655913036040429856040547350201210110762349430643045046234078839149491942329381864843107866701723407607741974711033593684694694169406410430554656560071416137693022833889306885688878041, 430499304718306891866201115084401634989700740766]
dsa_message_4 = 12349340274923748273047238423779003243
dsa_k_4 = 274255964315013103310470002241759069279328479420
dsa_signature_4 = [895249920656398544440263271759199387010282730919, 381589108127308645065905596312217765314221873978]
dsa_k_4b = 734554033512771934884924426716368720279316858082
dsa_signature_4b = [1087722479084406294517580512574588838651279256621, 1018406424859379609712339386033082327498728335426]

dsa_pubkey_5 = [107112836042878869662948719965221578297584308760082079001539905695865044477689255418462511424282585613015840457983838111657234228820429578276851514002497142678238216553125992920516941493884725299703540245235891132730953953509319859348868814400305758294867665191840845859338522935730585528413903421445661251801, 1020458253773880113530184007855901420707973488701, 22931994516515001892475476119954837438363821814921668535034624121296622661126233752513333229233863800007959271056580230268424251259378226530037341896658185241679500130974163063815569966801970448920723231277263726160852186018568179858201623995690874139980947166253325774466995650598855102671348437271521544044, 32627415125504951557756848701040929235273265227822012912872624474177244793089273018448049211825481129299495689567961623761829750405107167688176620257409710069344495280561534052355812946952189109850566283836294931604500093653837493847277650923260069834985131862107672431358066904921651100856879001339013647426]
dsa_privkey_5 = [107112836042878869662948719965221578297584308760082079001539905695865044477689255418462511424282585613015840457983838111657234228820429578276851514002497142678238216553125992920516941493884725299703540245235891132730953953509319859348868814400305758294867665191840845859338522935730585528413903421445661251801, 1020458253773880113530184007855901420707973488701, 22931994516515001892475476119954837438363821814921668535034624121296622661126233752513333229233863800007959271056580230268424251259378226530037341896658185241679500130974163063815569966801970448920723231277263726160852186018568179858201623995690874139980947166253325774466995650598855102671348437271521544044, 901185958220008464638758819029610336786894240286]
dsa_message_5 = 299231203130193810380138019301230833193
dsa_k_5 = 682526212564495214862983575545858672004690063321
dsa_signature_5 = [425495223541359213328060583126872936343717190970, 753153177547236555169341144261701337337284058700]





def assert_between(self, value, mn, mx):
    """Fail if value is not between mn and mx (inclusive)."""
    self.assertGreaterEqual(value, mn)
    self.assertLessEqual(value, mx)


class Test_1_1_DSAGenKey(unittest.TestCase):

    def test_1(self):
        L = 256
        N = 25
        pub, priv = uoc_dsa_genkey(L, N)

        self.assertEqual(pub[0], priv[0])
        self.assertEqual(pub[1], priv[1])
        self.assertEqual(pub[2], priv[2])

        p, q, g, y = pub
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)

        p, q, g, y = priv
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)

    def test_2(self):
        L = 512
        N = 50
        pub, priv = uoc_dsa_genkey(L, N)

        self.assertEqual(pub[0], priv[0])
        self.assertEqual(pub[1], priv[1])
        self.assertEqual(pub[2], priv[2])

        p, q, g, y = pub
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)

        p, q, g, y = priv
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)

    def test_3(self):
        L = 1024
        N = 160
        pub, priv = uoc_dsa_genkey(L, N)

        self.assertEqual(pub[0], priv[0])
        self.assertEqual(pub[1], priv[1])
        self.assertEqual(pub[2], priv[2])

        p, q, g, y = pub
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)

        p, q, g, y = priv
        assert_between(self, q.bit_length(), N-1, N)
        assert_between(self, p.bit_length(), L-1, L)




class Test_1_2_DSASign(unittest.TestCase):

    def test_1(self):
        UOCRandom.random_values = [dsa_k_4]*10
        signature = uoc_dsa_sign(dsa_privkey_4, dsa_message_4)
        self.assertEqual(dsa_signature_4, signature)

    def test_2(self):
        UOCRandom.random_values = [dsa_k_4b]*10
        signature = uoc_dsa_sign(dsa_privkey_4, dsa_message_4)
        self.assertEqual(dsa_signature_4b, signature)

    def test_3(self):
        UOCRandom.random_values = [dsa_k_5]*10
        signature = uoc_dsa_sign(dsa_privkey_5, dsa_message_5)
        self.assertEqual(dsa_signature_5, signature)


class Test_1_3_DSAVerify(unittest.TestCase):

    def test_1(self):
        message = 33
        signature = (700405676731191935445567802754090535698695992518, 
                     835346461564364095191531020386560371281598134065)
        r = uoc_dsa_verify(dsa_pubkey_1, message, signature);
        self.assertEqual(True, r)

    def test_2(self):
        message = 33
        signature = (559541167055182313138290295441828419049234732758, 
                     627346053564021107207456327339298029082829791252)
        r = uoc_dsa_verify(dsa_pubkey_2, message, signature);
        self.assertEqual(True, r)

    def test_3(self):
        message = 33
        signature = (256501034251615333017386700935652815400546217949, 
                     1036268173395184930332022536522574504676947493055)
        r = uoc_dsa_verify(dsa_pubkey_2, message, signature);
        self.assertEqual(True, r)

    def test_4(self):
        message = 33
        signature = (221196686170536630373708688762726195444476387361, 
                     918298663086035244460774285472254775855297713787)
        r = uoc_dsa_verify(dsa_pubkey_2, message, signature);
        self.assertEqual(True, r)

    def test_5(self):
        message = 33
        signature = (948827789346760379537111727844714757731807530183, 
                     830729534752678471280846515384378960747262970832)
        r = uoc_dsa_verify(dsa_pubkey_3, message, signature);
        self.assertEqual(True, r)

    def test_6(self):
        r = uoc_dsa_verify(dsa_pubkey_4, dsa_message_4, dsa_signature_4);
        self.assertEqual(True, r)

    def test_7(self):
        r = uoc_dsa_verify(dsa_pubkey_4, dsa_message_4, dsa_signature_4b);
        self.assertEqual(True, r)

    def test_8(self):
        r = uoc_dsa_verify(dsa_pubkey_5, dsa_message_5, dsa_signature_5);
        self.assertEqual(True, r)

    def test_8(self):
        r = uoc_dsa_verify(dsa_pubkey_5, dsa_message_5, [0, 0]);
        self.assertEqual(False, r)

    def test_9(self):
        L = 512
        N = 50
        message = 12345
        pub, priv = uoc_dsa_genkey(L, N)
        signature = uoc_dsa_sign(priv, message)
        r = uoc_dsa_verify(pub, message, signature);
        self.assertEqual(True, r)





class Test_2_1_SHA1(unittest.TestCase):

    def test_1(self):
        r = uoc_sha1("CRYPTOGRAPHY", 4);
        self.assertEqual("0", r)

    def test_2(self):
        r = uoc_sha1("ISTHEPRACTICEANDSTUDYOFTECHNIQUESFORSECURECOMMUNICATION", 8);
        self.assertEqual("f8", r)

    def test_3(self):
        r = uoc_sha1("NSA", 12);
        self.assertEqual("5ac", r)

    def test_4(self):
        r = uoc_sha1("ISAUSINTELLIGENCEAGENCY", 16);
        self.assertEqual("73cb", r)

    def test_5(self):
        r = uoc_sha1("FREEDOMOFSPEECH", 20);
        self.assertEqual("ba465", r)

    def test_6(self):
        r = uoc_sha1("ISARIGHT", 24);
        self.assertEqual("e83bd9", r)

    def test_7(self):
        r = uoc_sha1("42", 28);
        self.assertEqual("797ae56", r)

    def test_8(self):
        r = uoc_sha1("SPEAKERSCORNER", 32);
        self.assertEqual("89ec9422", r)

    def test_9(self):
        r = uoc_sha1("LONDON", 36);
        self.assertEqual("768282fff", r)


class Test_2_2_SHA1PreImages(unittest.TestCase):

    def test_1(self):
        r = uoc_sha1_find_preimage("CRYPTOGRAPHY", 4);
        self.assertEqual("0", uoc_sha1(r, 4))

    def test_2(self):
        r = uoc_sha1_find_preimage("ISTHEPRACTICEANDSTUDYOFTECHNIQUESFORSECURECOMMUNICATION", 8);
        self.assertEqual("f8", uoc_sha1(r, 8))

    def test_3(self):
        r = uoc_sha1_find_preimage("NSA", 12);
        self.assertEqual("5ac", uoc_sha1(r, 12))

    def test_4(self):
        r = uoc_sha1_find_preimage("ISAUSINTELLIGENCEAGENCY", 16);
        self.assertEqual("73cb", uoc_sha1(r, 16))



class Test_2_3_SHA1Collisions(unittest.TestCase):

    def test_1(self):
        r = uoc_sha1_collisions(4);
        self.assertNotEqual(r[0], r[1])
        self.assertEqual(uoc_sha1(r[0],4), uoc_sha1(r[1],4))

    def test_2(self):
        r = uoc_sha1_collisions(8);
        self.assertNotEqual(r[0], r[1])
        self.assertEqual(uoc_sha1(r[0],8), uoc_sha1(r[1],8))

    def test_3(self):
        r = uoc_sha1_collisions(16);
        self.assertNotEqual(r[0], r[1])
        self.assertEqual(uoc_sha1(r[0],16), uoc_sha1(r[1],16))




class Test_3_1_DSAAttack(unittest.TestCase):

    def test_1(self):
        L = 32
        N = 10

        pub = [3703514891, 577, 1464643535, 1457336885]
        priv = [3703514891, 577, 1464643535, 226]
        k = 97

        m1 = 5
        UOCRandom.random_values = [k]*10
        s1 = uoc_dsa_sign(priv, m1)

        m2 = 71
        UOCRandom.random_values = [k]*10
        s2 = uoc_dsa_sign(priv, m2)

        fake_priv = uoc_dsa_extract_private_key(pub, m1, s1, m2, s2)
        self.assertEqual(priv, fake_priv)


    def test_2(self):

        pub = [3572929247, 911, 3234738239, 458433058] 
        priv = [3572929247, 911, 3234738239, 336]
        k = 43

        m1 = 9
        UOCRandom.random_values = [k]*10
        s1 = uoc_dsa_sign(priv, m1)

        m2 = 51
        UOCRandom.random_values = [k]*10
        s2 = uoc_dsa_sign(priv, m2)

        fake_priv = uoc_dsa_extract_private_key(pub, m1, s1, m2, s2)
        self.assertEqual(priv, fake_priv)


    def test_3(self):
        pub = [4018678577, 569, 2277027328, 517421301]
        priv = [4018678577, 569, 2277027328, 21]
        k = 13

        m1 = 5
        UOCRandom.random_values = [k]*10
        s1 = uoc_dsa_sign(priv, m1)

        m2 = 7
        UOCRandom.random_values = [k]*10
        s2 = uoc_dsa_sign(priv, m2)

        fake_priv = uoc_dsa_extract_private_key(pub, m1, s1, m2, s2)
        self.assertEqual(priv, fake_priv)


    def test_4(self):
        L = 32
        N = 10
        pub, priv = uoc_dsa_genkey(L, N)
        k = random.randint(1, pub[1]-1)

        m1 = 5
        UOCRandom.random_values = [k]*10
        s1 = uoc_dsa_sign(priv, m1)

        m2 = 7
        UOCRandom.random_values = [k]*10
        s2 = uoc_dsa_sign(priv, m2)

        fake_priv = uoc_dsa_extract_private_key(pub, m1, s1, m2, s2)
        self.assertEqual(priv, fake_priv)


class Test_3_2_DSADeterministicSign(unittest.TestCase):

    def test_1(self):
        UOCRandom.random_values = []
        exp_signature = [81484265029530616344422533963512365513832941842, 
                         98438195917056814812018450155944949017279105090]
        signature = uoc_dsa_deterministic_sign(dsa_privkey_4, dsa_message_4)
        self.assertEqual(exp_signature, signature)

    def test_2(self):
        UOCRandom.random_values = []
        exp_signature = [127912981836496154554189027951659212769337717125, 
                         201888920637326362567124138735030504197628137090]
        signature = uoc_dsa_deterministic_sign(dsa_privkey_5, dsa_message_5)
        self.assertEqual(exp_signature, signature)

    def test_3(self):
        UOCRandom.random_values = []
        exp_signature = [497433550492872121244895922825051746692528075472, 
                         1278521960864081873737909639954113319492981205418]
        signature = uoc_dsa_deterministic_sign(dsa_privkey_4, 666)
        self.assertEqual(exp_signature, signature)

    def test_4(self):
        UOCRandom.random_values = []
        exp_signature =  [884017578317422195395183019332005570692618825999, 
                          645797192736123364483966414272305987421013610358]
        signature = uoc_dsa_deterministic_sign(dsa_privkey_5, 1729)
        self.assertEqual(exp_signature, signature)



if __name__ == '__main__':

    # create a suite with all tests
    test_classes_to_run = [Test_1_1_DSAGenKey,
                           Test_1_2_DSASign,
                           Test_1_3_DSAVerify,
                           Test_2_1_SHA1,
                           Test_2_2_SHA1PreImages,
                           Test_2_3_SHA1Collisions,
                           Test_3_1_DSAAttack,
                           Test_3_2_DSADeterministicSign
                           ]
    loader = unittest.TestLoader()
    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    all_tests_suite = unittest.TestSuite(suites_list)

    # run the test suite with high verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(all_tests_suite)



