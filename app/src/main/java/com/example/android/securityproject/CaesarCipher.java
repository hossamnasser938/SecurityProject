package com.example.android.securityproject;

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
            //get ASCI code of current character
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

}
