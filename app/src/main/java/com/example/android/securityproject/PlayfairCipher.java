package com.example.android.securityproject;

import java.util.ArrayList;

public class PlayfairCipher {

    /**
     * encrypts a plaintext into a ciphertext using the given key based on Playfair encryption algorithm
     * @param plaintext is the text to be encrypted
     * @param key is the word to be used in encryption
     * @return the encrypted text(ciphertext)
     */
    public static String encrypt(String plaintext, String key){
        //Declare ciphertext string builder
        StringBuilder ciphertextBuilder = new StringBuilder();

        //Construct the 5*5 matrix from the key
        char[][] matrix = constructMatrix(key);

        //Construct the pairs of characters from the plaintext
        ArrayList<String> plaintextPairs = generatePlaintextPairs(plaintext);

        for(int i = 0, length = plaintextPairs.size(); i < length; i++){
            int[] firstCharIndex = getIndex(plaintextPairs.get(i).charAt(0), matrix);
            int[] secondCharIndex = getIndex(plaintextPairs.get(i).charAt(1), matrix);

            if(firstCharIndex[0] == secondCharIndex[0]){    //Two chars at the same row
                //Calculate the indices of encrypted characters in the matrix
                int encryptedRowIndex = firstCharIndex[0];
                int encryptedFirstColumnIndex = (firstCharIndex[1] + 1) % 5;
                int encryptedSecondColumnIndex = (secondCharIndex[1] + 1) % 5;

                //Append the encrypted characters to the ciphertext
                ciphertextBuilder.append(matrix[encryptedRowIndex][encryptedFirstColumnIndex]);
                ciphertextBuilder.append(matrix[encryptedRowIndex][encryptedSecondColumnIndex]);
            }
            else if(firstCharIndex[1] == secondCharIndex[1]){   //Two chars at the same column
                //Calculate the indices of encrypted characters in the matrix
                int encryptedColumnIndex = firstCharIndex[1];
                int encryptedFirstRowIndex = (firstCharIndex[0] + 1) % 5;
                int encryptedSecondRowIndex = (secondCharIndex[0] + 1) % 5;

                //Append the encrypted characters to the ciphertext
                ciphertextBuilder.append(matrix[encryptedFirstRowIndex][encryptedColumnIndex]);
                ciphertextBuilder.append(matrix[encryptedSecondRowIndex][encryptedColumnIndex]);
            }
            else{   //Two chars with different rows and columns
                int encryptedFirstRowIndex = firstCharIndex[0];
                int encryptedFirstColumnIndex = secondCharIndex[1];
                int encryptedSecondRowIndex = secondCharIndex[0];
                int encryptedSecondColumnIndex = firstCharIndex[1];

                //Append the encrypted characters to the ciphertext
                ciphertextBuilder.append(matrix[encryptedFirstRowIndex][encryptedFirstColumnIndex]);
                ciphertextBuilder.append(matrix[encryptedSecondRowIndex][encryptedSecondColumnIndex]);
            }
        }

        return ciphertextBuilder.toString();
    }

    /**
     * decrypts a ciphertext into a plaintext using the given key based on Playfair encryption algorithm
     * @param ciphertext is the text to be decrypted
     * @param key is the word to be used in decryption
     * @return the decrypted text(plaintext)
     */
    public static String decrypt(String ciphertext, String key){
        //Declare plaintext string builder
        StringBuilder plaintextBuilder = new StringBuilder();

        //Construct the 5*5 matrix from the key
        char[][] matrix = constructMatrix(key);

        //Construct the pairs of characters from the ciphertext
        ArrayList<String> ciphertextPairs = generatePlaintextPairs(ciphertext);

        for(int i = 0, length = ciphertextPairs.size(); i < length; i++){
            int[] firstCharIndex = getIndex(ciphertextPairs.get(i).charAt(0), matrix);
            int[] secondCharIndex = getIndex(ciphertextPairs.get(i).charAt(1), matrix);

            if(firstCharIndex[0] == secondCharIndex[0]){    //Two chars at the same row
                //Calculate the indices of decrypted characters in the matrix
                int decryptedRowIndex = firstCharIndex[0];
                int decryptedFirstColumnIndex = (firstCharIndex[1] - 1 + 5) % 5;
                int decryptedSecondColumnIndex = (secondCharIndex[1] - 1 + 5) % 5;

                //Append the decrypted characters to the plaintext
                plaintextBuilder.append(matrix[decryptedRowIndex][decryptedFirstColumnIndex]);
                plaintextBuilder.append(matrix[decryptedRowIndex][decryptedSecondColumnIndex]);
            }
            else if(firstCharIndex[1] == secondCharIndex[1]){   //Two chars at the same column
                //Calculate the indices of decrypted characters in the matrix
                int decryptedColumnIndex = firstCharIndex[1];
                int decryptedFirstRowIndex = (firstCharIndex[0] - 1 + 5) % 5;
                int decryptedSecondRowIndex = (secondCharIndex[0] - 1 + 5) % 5;

                //Append the decrypted characters to the plaintext
                plaintextBuilder.append(matrix[decryptedFirstRowIndex][decryptedColumnIndex]);
                plaintextBuilder.append(matrix[decryptedSecondRowIndex][decryptedColumnIndex]);
            }
            else{   //Two chars with different rows and columns
                int decryptedFirstRowIndex = firstCharIndex[0];
                int decryptedFirstColumnIndex = secondCharIndex[1];
                int decryptedSecondRowIndex = secondCharIndex[0];
                int decryptedSecondColumnIndex = firstCharIndex[1];

                //Append the encrypted characters to the ciphertext
                plaintextBuilder.append(matrix[decryptedFirstRowIndex][decryptedFirstColumnIndex]);
                plaintextBuilder.append(matrix[decryptedSecondRowIndex][decryptedSecondColumnIndex]);
            }
        }

        return plaintextBuilder.toString();
    }

    /**
     * construct the matrix to be used in encryption/decryption
     * @param key
     * @return
     */
    private static char[][] constructMatrix(String key){
        //Declare the matrix
        char[][] matrix = new char[5][5];

        //Remove whitespaces from the key
        key = key.replaceAll("\\s", "");

        //Replace all 'j' with 'i' in the key
        key = key.replaceAll("j", "i");

        //Construct a string builder from the key after lowercasing
        StringBuilder keyBuilder = new StringBuilder(key.toLowerCase());
        //Append English alphabets to the string builder
        keyBuilder.append(Constants.ENGLISH_ALPHABET);

        //Remove duplicate characters from the string builder
        for(int i = 1; i < keyBuilder.length(); i++){
            for(int j = i - 1; j >= 0; j--){
                if(keyBuilder.charAt(i) == keyBuilder.charAt(j)){
                    keyBuilder.deleteCharAt(i);
                    i--;
                }
            }
        }

        //Remove character j from the string builder
        keyBuilder.deleteCharAt(keyBuilder.indexOf("j"));

        //Fill the 25 characters from the string builder into the matrix
        for(int i = 0; i < 5; i++){
            for(int j = 0 ; j < 5; j++){
                matrix[i][j] = keyBuilder.charAt(5 * i + j);
            }
        }

        return matrix;
    }

    /**
     * divides the plaintext into pairs of characters and add necessary xs between duplicate characters
     * @param plaintext
     * @return
     */
    private static ArrayList<String> generatePlaintextPairs(String plaintext){
        //Declare the Arraylist
        ArrayList<String> pairs = new ArrayList<>();

        //remove whitespaces from the plaintext
        plaintext = plaintext.replaceAll("\\s", "");

        //Replace all 'j' with 'i' in the plaintext
        plaintext = plaintext.replaceAll("j", "i");

        //Construct a string builder from the plaintext after lowercasing
        StringBuilder plaintextBuilder = new StringBuilder(plaintext.toLowerCase());

        //Add xs required between duplicate characters
        for(int i = 1; i < plaintextBuilder.length(); i += 2){
            if(plaintextBuilder.charAt(i) == plaintextBuilder.charAt(i - 1)) {
                plaintextBuilder.insert(i, 'x');
            }
        }

        //Check if the plaintext needs x at the end
        if(plaintextBuilder.length() % 2 != 0){
            plaintextBuilder.append('x');
        }

        //Add pairs to the plaintext
        for(int i = 1, length = plaintextBuilder.length(); i < length; i += 2){
            pairs.add(plaintextBuilder.substring(i - 1, i + 1));
        }

        return pairs;
    }

    /**
     * gets the row and column of a specific character in the matrix
     * @param character
     * @param matrix
     * @return an array of integers of size 2, the first element is the row index, the second element is the column index
     */
    private static int[] getIndex(char character, char[][] matrix){
        //Declare the array that holds crow and column indices respectively
        int[] index = new int[2];

        //Iterate over the matrix to find the character
        for(int i = 0; i < 5; i++){
            for(int j = 0; j < 5; j++){
                if(character == matrix[i][j]){
                    index[0] = i;
                    index[1] = j;
                }
            }
        }

        return index;
    }

}
