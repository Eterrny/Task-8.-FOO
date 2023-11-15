import java.security.InvalidParameterException;

public class FOO {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Входные параметры отсутствуют");
            return;
        }
        if (args[0].equals("/help") || args[0].equals("h")) {
            System.out.println("""
                    Программе должны передаваться следующие параметры:
                    \t- число участников голосования
                    \t- число избираемых""");
            return;
        }
        if (args.length < 2) {
            System.out.println("Передано некорректное число параметров.");
            return;
        }
        int voterCount, electedCount;
        try {
            voterCount = Integer.parseInt(args[0]);
            electedCount = Integer.parseInt(args[1]);
            if (voterCount < 1 || electedCount < 1) {
                throw new InvalidParameterException("Количество голосующих и избираемых должно быть положительным числом.");
            }
        } catch (IndexOutOfBoundsException e) {
            System.out.println("Выход за пределы массива.");
            return;
        } catch (NumberFormatException e) {
            System.out.println("Ошибка при чтении входных параметров.");
            return;
        } catch (InvalidParameterException e){
            System.out.println(e.getMessage());
            return;
        }
        FOOService service = new FOOService(voterCount, electedCount);
        service.step1();
    }
}
