import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;

public class FOOService {
    private final int electedCount;
    private ArrayList<Voter> voters = new ArrayList<>();
    private ArrayList<Integer> elected = new ArrayList<>();
    private Counter counter;

    private Administrator admin;

    private boolean withoutAccessTest = false;
    private boolean step5Test = false;
    private boolean step7Test = false;

    private boolean errorCheckSignature = false;

    public FOOService(int voterCount, int electedCount) {
        for (int i = 0; i < voterCount; ++i) {
            voters.add(new Voter(i));
        }
        this.electedCount = electedCount;
        for (int i = 1; i <= electedCount; ++i) {
            elected.add(i);
        }
        System.out.printf("Количество голосующих: %d\nКоличество избираемых: %d\n", this.voters.size(), this.electedCount);
    }

    public void step1() {
        System.out.println("\n--- Шаг 1 ---\nГолосующие сгенерировали ключи для асимметричного шифрования:");
        for (int i = 0; i < voters.size(); ++i) {
            System.out.printf("""
                    Голосующий %d:
                        privateKey = %s
                        publicKey = %s
                    """,
//                    i, RSAService.convertPrivateKeyToString(voters.get(i).getPrivateKey()).substring(0, 40) + "...", RSAService.convertPublicKeyToString(voters.get(i).getPublicKey()).substring(0, 40) + "...");
                    i, voters.get(i).getPrivateKey(), voters.get(i).getPublicKey());
        }
        this.step2();
    }

    private void step2() {
        this.counter = new Counter(electedCount);
        System.out.printf("""
                \n--- Шаг 2 ---
                Счетчик генерирует ключи, публичный ключ рассказывается всем:
                   c_privateKey: %s,
                   c_publicKey: %s
                   """, counter.getPrivateKey(), counter.getPublicKey());
        for (Voter voter : voters) {
            voter.setCounterKey(counter.getPublicKey());
        }
        this.step3();
    }

    private void step3() {
        this.admin = new Administrator();
        if (withoutAccessTest) {
            Random rnd = new Random();
            int bound = rnd.nextInt(voters.size());
            for(int i = 0; i < bound; ++i) {
                admin.addVoterWithAccess(rnd.nextInt(voters.size()));
            }
        }
        admin.setCounterKey(counter.getPublicKey());
        counter.setAdminKey(admin.getPublicKey());
        for (Voter voter : voters) {
            voter.setN(admin.getN());
            voter.setAdminKey(admin.getPublicKey());
            admin.registrateVoter(voter);
        }
        System.out.printf("""
                        \n--- Шаг 3 ---
                        Регистратор генерирует ключи, публичный ключ рассказывается всем:
                           c_privateKey: %s,
                           c_publicKey: %s
                        Затем регистратор выкладывает список голосующих: %s
                        """,
                admin.getPrivateKey(), admin.getPublicKey(), admin.printListOfVoters());
        if (withoutAccessTest){
            return;
        }
        this.step4and5and6();
    }

    private void step4and5and6() {
        System.out.println("\n--- Шаг 4, 5, 6 ---");
        for (Voter voter : voters) {
            voter.generateSymmetricKey();
            voter.makeChoiceAndEncrypt(elected);
            voter.blindAndSign();
            System.out.printf("""
                            ---
                            Голосующий %d:
                               Генерирует ключ для симметричного шифрования: %s
                               Делает выбор в бюллетене: choice = %d
                               Шифрует бюллетень: encChoice = %s = %d
                               Генерирует r = %d и с его помощью скрывает содержимое бюллетеня encChoiceBlind = %d
                               Подписывает зашифрованный скрытый бюллетень: %s,
                               Отправляет регистратору encChoiceBlind, подпись и свой публичный ключ
                                                
                            """,
                    voter.getId(),
                    AESService.convertSecretKeyToString(voter.getAesKey()),
                    voter.getChoice(),
                    voter.getEncChoice(),
                    voter.getEncChoiceSHA(),
                    voter.getR(),
                    voter.getEncChoiceBlind(),
                    voter.getSignature());
            if (step5Test) {
                voter.changeSignature();
            }
            BigInteger encChoiceBlindSigned = admin.sendBallot(voter.getEncChoiceBlind(), voter.getSignature(), voter.getPublicKey());
            if (encChoiceBlindSigned == null) {
                this.errorCheckSignature = true;
                return;
            }
            System.out.printf("""
                            Регистратор:
                               Принимает сообщение и проверяет, что оно подписано легитимным голосующим
                               Подписывает вслепую сообщение: encChoiceBlindSigned = %d
                               Отправляет encChoiceBlindSigned голосующему
                               
                            """,
                    encChoiceBlindSigned);
            voter.setEncChoiceBlindSigned(encChoiceBlindSigned);
            voter.unblind();
            System.out.printf("""
                            Голосующий раскрывает бюллетень с помощью числа r:
                               encChoiceSigned = %d
                            ---
                            """,
                    voter.getEncChoiceSigned());
        }
        this.step7();
    }

    private void step7() {
        System.out.println("\n--- Шаг 7 ---");
        for (Voter voter : voters) {
//            System.out.println("\n i = " + voter.getId() + "\ngetEncChoice = " + voter.getEncChoice() + "\ngetEncChoiceSHA = " + voter.getEncChoiceSHA()
//                    + "\ngetEncChoiceSigned = " + voter.getEncChoiceSigned() + "\ngetN = " +  voter.getN());
            if (step7Test) {
                voter.changeEncChoiceSigned();
            }
            counter.takeEncChoiceSigned(voter.getEncChoice(), voter.getEncChoiceSHA(), voter.getEncChoiceSigned(), voter.getN());
            if (!step7Test) {

                System.out.printf("""
                                ---
                                Голосующий %d отправляет счетчику:
                                   encChoice = %d
                                   encChoiceSigned = %d
                                                    
                                Счетчик:
                                   Проверяет, что encChoiceSigned действительно подписал регистратор
                                   Помещает encChoice в специальный список в открытом доступе после оговоренного времени
                                ---
                                """,
                        voter.getId(),
                        voter.getEncChoiceSHA(),
                        voter.getEncChoiceSigned());
            }
        }
        System.out.println("\nГолосованиие окончено. Счетчик опубликовал список: " + counter.getEncChoices());
        this.step8();
    }

    private void step8() {
        System.out.println("\n--- Шаг 8 ---");
        for (Voter voter : voters) {
            counter.decryptAndUpdateResults(voter.findInList(counter.getEncChoices()), voter.getAesKey(), voter.getIv());
        }
        counter.publishResults();
    }

    public Administrator getAdmin() {
        return admin;
    }

    public Counter getCounter() {
        return counter;
    }

    public ArrayList<Voter> getVoters() {
        return voters;
    }

    public void setWithoutAccessTest(boolean withoutAccessTest) {
        this.withoutAccessTest = withoutAccessTest;
    }

    public void setStep5Test() {
        this.step5Test = true;
    }

    public boolean checkErrorSignature() {
        return errorCheckSignature;
    }

    public void setStep7Test() {
        this.step7Test = true;
    }
}
