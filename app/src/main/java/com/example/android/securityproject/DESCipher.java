package com.example.android.securityproject;

import java.util.ArrayList;

public class DESCipher {

    /**
     * Encrypts a string using a key all given by the user
     * @param plaintext
     * @param userKey
     * @return
     * @throws Exception
     */
    public static String encrypt(String plaintext, String userKey) throws Exception {
        //Generate plaintext blocks
        ArrayList<String> plaintextBlocks = generateBinaryBlocks(plaintext);

        //Generate DES key from user key
        String DESKey = generateBinaryKey(userKey);

        //Generate subkeys
        ArrayList<String> subkeys = generateSubkeys(DESKey);

        //Cipher blocks
        StringBuilder binaryCiphertext = new StringBuilder();
        for(int i = 0, size = plaintextBlocks.size(); i < size; i++){
            //Get current plaintext block
            String plaintextBlock = plaintextBlocks.get(i);
            //Cipher this block
            String cipheredBlock = cipher(plaintextBlock, subkeys);
            //Append to binary ciphertext
            binaryCiphertext.append(cipheredBlock);
        }

        String ciphertext = binaryToCharacters(binaryCiphertext.toString());

        return ciphertext;
    }


    /**
     * Decrypts a string using a key all given by the user
     * @param ciphertext
     * @param userKey
     * @return
     * @throws Exception
     */
    public static String decrypt(String ciphertext, String userKey) throws Exception {
        //Generate ciphertext blocks
        ArrayList<String> ciphertextBlocks = generateBinaryBlocks(ciphertext);

        //Generate DES key from user key
        String DESKey = generateBinaryKey(userKey);

        //Generate subkeys
        ArrayList<String> subkeys = generateSubkeys(DESKey);

        //Decipher blocks
        StringBuilder binaryPlaintext = new StringBuilder();
        for(int i = 0, size = ciphertextBlocks.size(); i < size; i++){
            //Get current ciphertext block
            String ciphertextBlock = ciphertextBlocks.get(i);
            //Decipher this block
            String decipheredBlock = decipher(ciphertextBlock, subkeys);
            //Append to binary plaintext
            binaryPlaintext.append(decipheredBlock);
        }

        String plaintext = binaryToCharacters(binaryPlaintext.toString());

        return plaintext;
    }


    /**
     * encrypts a block of plaintext
     * @param block
     * @param subkeys
     * @return
     * @throws Exception if the block's length is not correct(!=64)
     */
    private static String cipher(String block, ArrayList<String> subkeys) throws Exception {
        //Remove white spaces
        block = block.replaceAll("\\s", "");

        //Assure that the block with correct length(64)
        int length = block.length();
        if(length != Constants.BLOCK_LENGTH){
            throw new Exception("Block should have length " + Constants.KEY_LENGTH);
        }

        //1-Permute the block based on IP
        block = permutation(block, Constants.IP_TABLE);

        //2-Split the block into two haves
        String left = block.substring(0, block.length() / 2);
        String right = block.substring(block.length() / 2);

        //3-Loop times of rounds
        for(int i = 0; i < Constants.NUMBER_OF_ROUNDS; i++){
            //4-Store the right half as temp
            String temp = right;

            //5-Calculate the right half
            right = xor(left, fun(right, subkeys.get(i)));

            //6-Calculate the left half
            left = temp;
        }

        //7-Reverse and concatenate the left and right halves forming result
        String result = right + left;

        //8-Permute the block based on FP
        result = permutation(result, Constants.FP_TABLE);

        //9-Return the result
        return result;
    }


    /**
     * decrypts a block of ciphertext
     * @param block
     * @param subkeys
     * @return
     * @throws Exception if the block's length is not correct(!=64)
     */
    private static String decipher(String block, ArrayList<String> subkeys) throws Exception {
        //Reverse the subkeys list
        ArrayList<String> reversedList = reverseList(subkeys);

        //Call cipher function with reversed list of subkeys
        return cipher(block, reversedList);
    }


    /**
     * Generates a subkey for each round
     * @param key
     * @return
     * @throws Exception if the key has incorrect length
     */
    private static ArrayList<String> generateSubkeys(String key) throws Exception {
        //Remove white spaces
        key = key.replaceAll("\\s", "");

        //Assure that the key with correct length(64)
        int length = key.length();
        if(length != Constants.KEY_LENGTH){
            throw new Exception("Key should have length " + Constants.KEY_LENGTH);
        }

        //Declare array list to hold subkeys
        ArrayList<String> subkeys = new ArrayList<>();

        //1-Permute the key based on PC-1
        key = permutation(key, Constants.PC_1_TABLE);

        //2-Split the key into two haves
        String left = key.substring(0, key.length() / 2);
        String right = key.substring(key.length() / 2);

        //3-Loop number of rounds
        for(int i = 0; i < Constants.NUMBER_OF_ROUNDS; i++){
            //4-Shift left the left half
            left = shiftLeft(left, Constants.SHIFT_TIMES[i]);

            //5-Shift left the right half
            right = shiftLeft(right, Constants.SHIFT_TIMES[i]);

            //6-Concatenate the left and right half resulting subkey
            String subkey = left + right;

            //7-Permute the subkey based on PC-2
            subkey = permutation(subkey, Constants.PC_2_TABLE);

            //8-Add subkey
            subkeys.add(subkey);
        }

        //9-return the array list of subkeys
        return subkeys;
    }


    /**
     * DES function
     * @param right
     * @param subkey
     * @return
     */
    private static String fun(String right, String subkey) throws Exception {
        //1-Expand the right part from 32-bit to 48-bit
        right = permutation(right, Constants.E_TABLE);

        //2-xor the right part with the subkey
        String result = xor(right, subkey);

        //3-Reduce the result from 48-bit to 32-bit using SBoxes
        result = fullSBoxing(result);

        //4-Perform permutation
        result = permutation(result, Constants.P_TABBLE);

        //5-return the result
        return result;
    }


    /**
     * Performs permutation and also Expansion using permutation table
     * @param instanceToBePermuted
     * @param permutationArray
     * @return
     */
    private static String permutation(String instanceToBePermuted, int permutationArray[]){
        //Remove white spaces _if exist_ from the instance to be permuted
        instanceToBePermuted = instanceToBePermuted.replaceAll("\\s", "");

        //Declare StringBuilder to append elements in based on the permutation array
        StringBuilder permuted = new StringBuilder();

        //Iterate over the permutation array
        for (int index : permutationArray) {
            //Append the current element based on the permutation array
            permuted.append(instanceToBePermuted.charAt(index - 1));
        }

        //return the string after permuting
        return permuted.toString();
    }


    /**
     * Given a 48-bit block, returns a 32-bit block using SBoxes
     * @param block
     * @return
     * @throws Exception if the block is not with correct length(48)
     */
    private static String fullSBoxing(String block) throws Exception{
        //Declare the String Builder to append results from SBoxes
        StringBuilder builder = new StringBuilder();

        //Remove white spaces _if exist_ from the block
        block = block.replaceAll("\\s", "");

        //Assure that the length of the block is correct(48)
        int length = block.length();
        if(length != Constants.SUBKEY_LENGTH){
            throw new Exception("Incorrect length, should be " + Constants.SUBKEY_LENGTH);
        }

        //Divide the block into parts to be feed to the SBoxes
        ArrayList<String> parts = new ArrayList<>();
        for(int i = 0; i < Constants.NUMBER_OF_SBOXES; i++){
            parts.add(block.substring(i * Constants.SBOX_INPUT_LENGTH, i * Constants.SBOX_INPUT_LENGTH + Constants.SBOX_INPUT_LENGTH));
        }

        //Iterate over all SBoxes
        for (int i = 0; i < Constants.NUMBER_OF_SBOXES; i++) {
            String part = partialSBoxing(parts.get(i), i);
            part = addNecessaryZeros(part, Constants.SBOX_OUTPUT_LENGTH);
            builder.append(part);
        }

        //return the result of SBoxing
        return builder.toString();
    }


    /**
     * Given a 6-bit part, returns 4-bit part using one of the SBoxes
     * @param part
     * @param SBoxNumber
     * @return
     * @throws Exception if the part is not with correct length(6)
     */
    private static String partialSBoxing(String part, int SBoxNumber) throws Exception {
        //Assure that the length of the part is correct(6)
        int length = part.length();
        if(length != Constants.SBOX_INPUT_LENGTH){
            throw new Exception("Incorrect part length, should be " + Constants.SBOX_INPUT_LENGTH);
        }

        //Divide the part into column and row indices
        String row = "" + part.charAt(0) + part.charAt(length - 1);
        String column = part.substring(1, length - 1);

        int rowIndex = Integer.parseInt(row, Constants.BINARY_BASE);
        int columnIndex = Integer.parseInt(column, Constants.BINARY_BASE);

        //Get the correct value from the SBox
        int result = Constants.SBOXES_TABLES[SBoxNumber][rowIndex][columnIndex];

        //Convert into String and return
        return Integer.toBinaryString(result);
    }


    /**
     * Add zeros to the binary number to satisfy a necessary length
     * @param binaryNumber
     * @param necessaryLength
     * @return
     */
    private static String addNecessaryZeros(String binaryNumber, int necessaryLength){
        //Check whether we need to add zeros or not
        int length = binaryNumber.length();
        if(length == necessaryLength){
            return binaryNumber;
        }

        //Declare a string builder to insert zeros
        StringBuilder builder = new StringBuilder(binaryNumber);

        //Insert necessary zeros
        for(int i = length; i < necessaryLength; i++){
            builder.insert(0, '0');
        }

        //Return the string in the builder
        return builder.toString();
    }


    /**
     * Performs circular shift keft on a binary number stored as string
     * @param binaryNumber
     * @param shiftNumbers
     * @return
     */
    private static String shiftLeft(String binaryNumber, int shiftNumbers){
        //Declare string builder to manipulate while shifting
        StringBuilder builder = new StringBuilder(binaryNumber);

        //Do number of shifts
        for(int i = 0; i < shiftNumbers; i++){
            //Circulate char at location 0
            char charTobeShifted = builder.charAt(0);
            builder.deleteCharAt(0);
            builder.append(charTobeShifted);
        }

        //Return the string after manipulation
        return builder.toString();
    }


    /**
     * Performs xor on two operands represented by strings
     * @param operand1
     * @param operand2
     * @return
     * @throws Exception if the two operands have different lengths
     */
    private static String xor(String operand1, String operand2) throws Exception {
        //Remove white spaces
        operand1 = operand1.replaceAll("\\s", "");
        operand2 = operand2.replaceAll("\\s", "");

        //Assure that the operands have the same length
        int length = operand1.length();
        if(length != operand2.length()){
            throw new Exception("Cannot xoring two operands with different length");
        }

        //Convert strings int integers
        Long longOperand1 = Long.parseLong(operand1, Constants.BINARY_BASE);
        long longOperand2 = Long.parseLong(operand2, Constants.BINARY_BASE);

        //perform xor
        Long longResult = longOperand1 ^ longOperand2;

        //Convert result from int to String
        String result = Long.toBinaryString(longResult);

        //Add necessary zeos
        result = addNecessaryZeros(result, length);

        //return the result
        return result;
    }


    /**
     * reverses a list of Strings
     * @param list
     * @return
     */
    private static ArrayList<String> reverseList(ArrayList<String> list){
        //Declare array list to hold reversed items
        ArrayList<String> reversedList = new ArrayList<>();

        //Iterate over list's items reversely
        for (int i = list.size() - 1; i >= 0; i--){
            //Get current item
            String item = list.get(i);

            //Add it to reersed list
            reversedList.add(item);
        }

        //Return the reversed list
        return reversedList;
    }


    /**
     * Convert the plaintext into its binary equivalent and divide it into blocks
     * @param plaintext
     * @return
     */
    private static ArrayList<String> generateBinaryBlocks(String plaintext){
        //Declare array list to hold blocks
        ArrayList<String> blocks = new ArrayList<>();

        //Convert the plaintext into its binary equivalent
        String wholeBlock = charactersToBinary(plaintext);

        //Calculate the length of the whole block
        int length = wholeBlock.length();

        if(length >= Constants.BLOCK_LENGTH){
            //Divide into complete blocks
            for(int i = 0; i < length / Constants.BLOCK_LENGTH; i++){
                String block = wholeBlock.substring(i * Constants.BLOCK_LENGTH , i * Constants.BLOCK_LENGTH + Constants.BLOCK_LENGTH);
                blocks.add(block);
            }
        }

        //Check if there exist remaining bits less than block size
        int remainingBits = length % Constants.BLOCK_LENGTH;
        if(remainingBits > 0){
            String block = wholeBlock.substring(length - remainingBits);
            block = addNecessaryZeros(block, Constants.BLOCK_LENGTH);
            blocks.add(block);
        }

        return blocks;
    }


    /**
     * Generates the key to be used in DES from a key given by the user
     * @param userKey
     * @return
     */
    private static String generateBinaryKey(String userKey){
        //Convert the string into its equivalent binary form
        String binaryKey = charactersToBinary(userKey);

        //Trim the key to its correct length
        binaryKey = binaryKey.substring(0, Constants.KEY_LENGTH);

        //Return the key
        return binaryKey;
    }


    /**
     * Converts a string of characters to its equivalent binary form
     * @param characters
     * @return
     */
    private static String charactersToBinary(String characters){
        //Remove white spaces
        characters = characters.replaceAll("\\s", "");

        //Declare a string builder to hold the binary equivalent to the string characters
        StringBuilder builder = new StringBuilder();

        //Convert the string into char arrays
        char[] chars = characters.toCharArray();

        //Iterate over bytes
        for (char c : chars) {
            //Convert byte into equivalent binary
            String binaryEquivalent = Integer.toBinaryString(c);

            //Add necessary zeros
            binaryEquivalent = addNecessaryZeros(binaryEquivalent, Constants.BYTE_SIZE);

            //Append current byte
            builder.append(binaryEquivalent);
        }

        //Return te string of the builder
        return builder.toString();
    }


    /**
     * Converts a string of binary to its equivalent characters form
     * @param binary
     * @return
     * @throws Exception
     */
    private static String binaryToCharacters(String binary) throws Exception {
        //Make sure that the binary string length is multiple of Block size(64)
        int length = binary.length();
        if(length % Constants.BLOCK_LENGTH != 0){
            throw new Exception("The binary string represents the blocks must be a multiple of " + Constants.BLOCK_LENGTH);
        }

        //Declare string builder to append characters in
        StringBuilder builder = new StringBuilder();

        for(int i = 0; i < length / Constants.BYTE_SIZE; i++){
            //Get current byte
            String byte_ = binary.substring(i * Constants.BYTE_SIZE, i * Constants.BYTE_SIZE + Constants.BYTE_SIZE);
            //Convert it into equivalent Asci
            int byteAsci = Integer.parseInt(byte_, Constants.BINARY_BASE);
            //Append the char represented by Asci
            builder.append((char)byteAsci);
        }

        return builder.toString();
    }

}
