import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class FOOServiceTest {
    @Test
    void testVotersWithoutAccess() {
        FOOService service = new FOOService(100, 3);
        service.setWithoutAccessTest(true);
        service.step1();
        int withAccess = service.getAdmin().getVotersWithAccess().size();
        System.out.println("Количество допущенных: " + withAccess);
        assertTrue(withAccess > 0 && withAccess == service.getAdmin().getVoters().size());
    }

    @Test
    void testCheckSignatureByAdmin() {
        FOOService service = new FOOService(5, 3);
        service.setStep5Test();
        service.step1();
        assertTrue(service.checkErrorSignature());
    }

    @Test
    void testCheckBlindSignatureByCounter() {
        FOOService service = new FOOService(5, 3);
        service.setStep7Test();
        service.step1();
        assertTrue(service.getCounter().checkErrorSign());
    }
}