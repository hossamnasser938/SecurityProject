package com.example.android.securityproject;

import android.util.Log;

public class CaesarCipher {

    /**
     * using Caesar cipher it encrypts a plaintext into ciphertext using the given key
     * @param plaintext is the string to be encrypted
     * @param key is the key to be used in encryption
     * @return the encrypted string "ciphertext"
     */
    public static String encrypt(String plaintext, int key){

        StringBuilder ciphertext = new StringBuilder();
        char currentCharacter;
        char encryptedChar;

        //iterate through characters within plaintext
        for(int i = 0; i < plaintext.length(); i++){
            //get current character
            currentCharacter = plaintext.charAt(i);

            //check if it is capital, small, or symbol
            if(currentCharacter >= Constants.A_ASCICODE && currentCharacter <= Constants.Z_ASCICODE){ //capital letter
                encryptedChar = (char) ((currentCharacter + key - Constants.A_ASCICODE) % Constants.CHARACTERS_COUNT + Constants.A_ASCICODE);
                ciphertext.append(encryptedChar);
            }
            else if(currentCharacter >= Constants.a_ASCICODE && currentCharacter <= Constants.z_ASCICODE){ //small letter
                encryptedChar = (char) ((currentCharacter + key - Constants.a_ASCICODE) % Constants.CHARACTERS_COUNT + Constants.a_ASCICODE);
                ciphertext.append(encryptedChar);
            }
            else{ //symbol
                //do nothing
                ciphertext.append(currentCharacter);
            }
        }

        //convert the string builder into string
        return ciphertext.toString();
    }

    /**
     * using Caesar cipher it decrypts a ciphertext into plaintext using the given key
     * @param ciphertext is the string to be decrypted
     * @param key is the key to be used in decryption
     * @return the decrypted string "plaintext"
     */
    public static String decrypt(String ciphertext, int key){

        StringBuilder plaintext = new StringBuilder();
        char currentCharacter;
        char decryptedChar;

        //iterate through characters within ciphertext
        for(int i = 0; i < ciphertext.length(); i++){
            //get current character
            currentCharacter = ciphertext.charAt(i);

            //check if it is capital, small, or symbol
            if(currentCharacter >= Constants.A_ASCICODE && currentCharacter <= Constants.Z_ASCICODE){ //capital letter
                decryptedChar = (char) ((currentCharacter - key - Constants.A_ASCICODE + Constants.CHARACTERS_COUNT) % Constants.CHARACTERS_COUNT + Constants.A_ASCICODE);
                plaintext.append(decryptedChar);
            }
            else if(currentCharacter >= Constants.a_ASCICODE && currentCharacter <= Constants.z_ASCICODE){ //small letter
                decryptedChar = (char) ((currentCharacter - key - Constants.a_ASCICODE + Constants.CHARACTERS_COUNT) % Constants.CHARACTERS_COUNT + Constants.a_ASCICODE);
                plaintext.append(decryptedChar);
            }
            else{ //symbol
                //do nothing
                plaintext.append(currentCharacter);
            }
        }

        //convert the string builder into string
        return plaintext.toString();
    }

}
