import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PontoIf {

    static Scanner sc = new Scanner(System.in);

    static class AESUtil {
        private static final String chave = "1234567890123456";

        public static String criptografar(String texto) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(chave.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(texto.getBytes()));
        }

        public static String descriptografar(String texto) throws Exception {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec key = new SecretKeySpec(chave.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(texto)));
        }
    }

    static class HashUtil {
        public static String sha256(String texto) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(texto.getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : hash) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            } catch (Exception e) {
                return null;
            }
        }
    }

    static class Professor {

        boolean presente;
        boolean logado;

        String cripUser;
        String userIDCripto;
        String senhaHash;

        void criarConta() throws Exception {
            System.out.print("Digite seu nome: ");
            String user = sc.nextLine();

            System.out.print("Digite seu ID: ");
            String userID = sc.nextLine();

            System.out.print("Crie uma senha: ");
            String senha = sc.nextLine();

            presente = false;
            logado = false;

            senhaHash = HashUtil.sha256(senha);
            cripUser = AESUtil.criptografar(user);
            userIDCripto = AESUtil.criptografar(userID);

            System.out.println("Conta criada com sucesso!");
        }

        void entrar() throws Exception {
            System.out.print("Digite seu usuário: ");
            String usuario = sc.nextLine();

            System.out.print("Digite sua senha: ");
            String senha = sc.nextLine();

            System.out.print("Digite seu ID: ");
            String id = sc.nextLine();

            String hashSenha = HashUtil.sha256(senha);

            String userSalvo = AESUtil.descriptografar(cripUser);
            String idSalvo = AESUtil.descriptografar(userIDCripto);

            if (usuario.equals(userSalvo) &&
                id.equals(idSalvo) &&
                hashSenha.equals(senhaHash)) {

                logado = true;
                System.out.println("Login feito com sucesso!");
                System.out.println("Olá " + userSalvo);

            } else {
                System.out.println("Credenciais incorretas!");
            }
        }

        void baterPontoEntrada() throws Exception {
            if (!logado) {
                System.out.println("Faça login primeiro!");
                return;
            }

            presente = true;
            String user = AESUtil.descriptografar(cripUser);
            LocalDateTime horario = LocalDateTime.now();

            System.out.println("Entrada registrada: " + user + " -> " + horario);
        }

        void baterPontoSaida() throws Exception {
            if (!logado) {
                System.out.println("Faça login primeiro!");
                return;
            }

            presente = false;
            String user = AESUtil.descriptografar(cripUser);
            LocalDateTime horario = LocalDateTime.now();

            System.out.println("Saída registrada: " + user + " -> " + horario);
        }
    }

    public static void main(String[] args) throws Exception {

        Professor prof = new Professor();
        char op, ponto;

        do {
            System.out.println("\n1- Criar conta");
            System.out.println("2- Entrar");
            System.out.println("3- Bater ponto");
            System.out.println("4- Sair");
            System.out.print("Opção: ");

            op = sc.next().charAt(0);
            sc.nextLine();

            switch (op) {

                case '1':
                    prof.criarConta();
                    break;

                case '2':
                    prof.entrar();
                    break;

                case '3':
                    System.out.println("1- Entrada");
                    System.out.println("2- Saída");
                    System.out.print("Opção: ");

                    ponto = sc.next().charAt(0);
                    sc.nextLine();

                    switch (ponto) {
                        case '1':
                            prof.baterPontoEntrada();
                            break;
                        case '2':
                            prof.baterPontoSaida();
                            break;
                        default:
                            System.out.println("Opção inválida!");
                    }
                    break;

                case '4':
                    System.out.println("Saindo...");
                    break;

                default:
                    System.out.println("Opção inválida!");
            }

        } while (op != '4');
    }
}