package com.example.android.securityproject

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    val TAG = "MainActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        handleUserInput()
    }

    private fun handleUserInput() {
        handleEncryptButton()
        handleDecryptButton()
    }

    private fun handleEncryptButton() {
        encrypt_button.setOnClickListener {
            Log.d(TAG, "encrypt button clicked")
            error_text_view.visibility = View.GONE

            val plaintext = input_field.text.toString().trim()
            Log.d(TAG, "plaintext : " + plaintext)
            val keyString = key_field.text.toString().trim()
            Log.d(TAG, "key : " + keyString)

            if (plaintext.isEmpty()) {
                Log.d(TAG, "empty plaintext")
                showError(R.string.enter_plaintext)
                return@setOnClickListener
            }

            if (keyString.isEmpty()) {
                Log.d(TAG, "empty key")
                showError(R.string.enter_key)
                return@setOnClickListener
            }

            when (algorithms_spinner.selectedItem) {
                resources.getString(R.string.choose_algorithm) -> {
                    Log.d(TAG, "did not choose algorithm")
                    showError(R.string.enter_algorithm)
                    return@setOnClickListener
                }
                resources.getString(R.string.caesar_cipher) -> {
                    val keyInt = keyString.toIntOrNull()
                    if (keyInt == null) {
                        Log.d(TAG, "invalid key")
                        showError(R.string.enter_valid_key)
                        return@setOnClickListener
                    }

                    Log.d(TAG, "chosen caesar cipher")
                    val output = CaesarCipher.encrypt(plaintext, keyInt)
                    output_field.text = output
                    Toast.makeText(this, R.string.encrypted, Toast.LENGTH_SHORT).show()
                }
                resources.getString(R.string.playfair_cipher) -> {
                    if(keyString.contains("/[^A-Za-z]/")) {
                        Log.d(TAG, "invalid key")
                        showError(R.string.enter_valid_key)
                        return@setOnClickListener
                    }

                    Log.d(TAG, "chosen playfair cipher")
                    val output = PlayfairCipher.encrypt(plaintext, keyString)
                    output_field.text = output
                    Toast.makeText(this, R.string.encrypted, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun handleDecryptButton() {
        decrypt_button.setOnClickListener {
            Log.d(TAG, "decrypt button clicked")
            error_text_view.visibility = View.GONE

            val ciphertext = input_field.text.toString().trim()
            Log.d(TAG, "ciphertext : " + ciphertext)
            val keyString = key_field.text.toString().trim()
            Log.d(TAG, "key : " + keyString)

            if (ciphertext.isEmpty()) {
                Log.d(TAG, "empty ciphertext")
                showError(R.string.enter_ciphertext)
                return@setOnClickListener
            }

            if (keyString.isEmpty()) {
                Log.d(TAG, "empty key")
                showError(R.string.enter_key)
                return@setOnClickListener
            }

            when (algorithms_spinner.selectedItem) {
                resources.getString(R.string.choose_algorithm) -> {
                    Log.d(TAG, "did not choose algorithm")
                    showError(R.string.enter_algorithm)
                    return@setOnClickListener
                }
                resources.getString(R.string.caesar_cipher) -> {
                    val keyInt = keyString.toIntOrNull()
                    if (keyInt == null) {
                        Log.d(TAG, "invalid key")
                        showError(R.string.enter_valid_key)
                        return@setOnClickListener
                    }

                    Log.d(TAG, "chosen caesar cipher")
                    val output = CaesarCipher.decrypt(ciphertext, keyInt)
                    output_field.text = output
                    Toast.makeText(this, R.string.decrypted, Toast.LENGTH_SHORT).show()
                }
                resources.getString(R.string.playfair_cipher) -> {
                    if(keyString.contains("/[^A-Za-z]/")) {
                        Log.d(TAG, "invalid key")
                        showError(R.string.enter_valid_key)
                        return@setOnClickListener
                    }

                    Log.d(TAG, "chosen playfair cipher")
                    val output = PlayfairCipher.decrypt(ciphertext, keyString)
                    output_field.text = output
                    Toast.makeText(this, R.string.decrypted, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun showError(stringId : Int){
        error_text_view.visibility = View.VISIBLE
        error_text_view.text = resources.getString(stringId)
    }
}
