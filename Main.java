package com;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class Main {

    static Scanner sc = new Scanner(System.in);

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String result = "";
        String key = "";
        Random r = new Random();
        String[] moves = args;
//        String[] moves = {"Rock", "Paper", "Scissors", "Lizard", "Spock"};
        int n = moves.length;
        key = createKey().toUpperCase();
        if (!checkMoves(moves)) {
            System.out.println("Wrong number of moves/duplicates of moves");
            System.exit(0);
        }
        String computerMove = moves[r.nextInt(moves.length)];
        int middle = moves.length / 2;
//        System.out.println(computerMove);
        byte[] hmacComputer = createHmac(key.getBytes(), computerMove.getBytes());
        System.out.println(String.format("HMAC: %032x", new BigInteger(1, hmacComputer)));
        int cMove = 0;
        System.out.println("Available moves: ");
        for (int i = 0; i < moves.length; i++) {
            System.out.println(i + 1 + ") " + moves[i]);
            if (moves[i].equals(computerMove)) cMove = i;
        }
        System.out.println("0) Exit");
        System.out.print("Enter your move: ");
        int hMove = Integer.parseInt(sc.nextLine());
        if (hMove == 0) {
            System.exit(0);
        }
        System.out.println("Your move: " + moves[hMove - 1]);
        result = (game(hMove - 1, middle, cMove, n));
        System.out.println("Computer's move: " + computerMove);
        System.out.println(result);
        System.out.println(key);
    }

    static boolean checkMoves(String[] moves) {
        List inputList = Arrays.asList(moves);
        Set inputSet = new HashSet(inputList);

        if (moves.length % 2 == 0 || moves.length == 1 || inputSet.size() < inputList.size()) {
            return false;
        }
        return true;
    }

    static String game(int move, int h, int compMove, int n) {
        String res = "";
        if(n == 3){
            if(compMove == move){
                res = "It's tie.";
            } else if((compMove == 0 && move == 1) || (compMove == 1 && move == 2) || (compMove == 2 && move == 0)){
                res = "You lose.";
            } else {
                res = "You win.";
            }
        } else{
            if (compMove == move) {
                res = "It's tie.";
            } else if (compMove >= move + h || compMove < move - h) {
                res = "You lose.";
            } else {
                res = "You win.";
            }
        }
        return res;
    }

    static byte[] createHmac(byte[] secretKey, byte[] message) {
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e);
        }
        return hmacSha256;
    }

    static String createKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom random = new SecureRandom();
        keyGen.init(random);
        SecretKey secretKey = keyGen.generateKey();
        String s = new BigInteger(1, secretKey.getEncoded()).toString(16);
        return s;
    }

}
