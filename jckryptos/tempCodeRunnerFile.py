@app.route('/get_password/<int:password_id>', methods=['GET'])
def get_password(password_id):
    # Step 1: Check if user is logged in
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Step 2: Fetch the encrypted password and associated key from the database
        query = """
            SELECT passwords.password_id, passwords.key_id, passwords.passwords, passwords.site, passwords.login_name,
                   passwords.title, `keys`.key_name, `keys`.`key`
            FROM passwords
            JOIN `keys` ON passwords.key_id = `keys`.key_id
            JOIN accounts ON `keys`.id = accounts.Id
            WHERE passwords.password_id = %s AND accounts.Id = %s
        """
        cur.execute(query, (password_id, user_id))
        result = cur.fetchone()

        if not result:
            print("Password not found or unauthorized access")
            return jsonify({'success': False, 'message': 'Password not found or unauthorized access'}), 404

        # Step 3: Get the encrypted password and encryption key
        encrypted_password = result['passwords']
        key_id = result['key_id']
        key_name = result['key_name']
        encryption_key = result['key']

        print(f"Fetched encrypted password for password_id {password_id} with key_id {key_id} and key_name '{key_name}'")

        # Step 4: Attempt to decrypt with the key associated with the key_name
        decryption_success = False
        try:
            fernet = Fernet(encryption_key.encode())
            decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
            decryption_success = True
            print(f"Successfully decrypted password_id {password_id} with key_name '{key_name}'")
        except InvalidToken:
            print(f"Decryption failed with key_name '{key_name}' for password_id {password_id}")
            decryption_success = False

        # Step 5: If decryption failed, attempt with other keys from the database
        if not decryption_success:
            # Fetch all keys except the one already tried
            cur.execute("SELECT key_id, key_name, `key` FROM `keys` WHERE key_id != %s", (key_id,))
            all_keys = cur.fetchall()
            for key_record in all_keys:
                alternative_key_name = key_record['key_name']
                alternative_encryption_key = key_record['key']
                try:
                    fernet = Fernet(alternative_encryption_key.encode())
                    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
                    decryption_success = True
                    print(f"Successfully decrypted password_id {password_id} with alternative key_name '{alternative_key_name}'")

                    # Re-encrypt with the correct key (original key associated with password)
                    correct_fernet = Fernet(encryption_key.encode())
                    new_encrypted_password = correct_fernet.encrypt(decrypted_password.encode()).decode()

                    # Update the password in the database with new encrypted password
                    update_query = """
                        UPDATE passwords
                        SET passwords = %s
                        WHERE password_id = %s
                    """
                    cur.execute(update_query, (new_encrypted_password, password_id))
                    mysql.connection.commit()
                    print(f"Re-encrypted and updated password_id {password_id} with key_name '{key_name}'")
                    break
                except InvalidToken:
                    print(f"Decryption failed with alternative key_name '{alternative_key_name}' for password_id {password_id}")
                    continue  # Try next key
            else:
                # If all keys fail
                print(f"Decryption failed for password_id {password_id} with all known keys")
                return jsonify({'success': False, 'message': 'Failed to decrypt the password'}), 500

        # Step 6: Prepare the response data
        response_data = {
            'password_id': password_id,
            'title': result['title'],
            'login_name': result['login_name'],
            'password': decrypted_password,  # Decrypted password
            'site': result['site'],
            'keys_name': key_name,
            'key_id': key_id,
            'url': result.get('url', '')
        }

        return jsonify(response_data), 200

    except Exception as e:
        print(f"Error retrieving password: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while retrieving the password'}), 500
    finally:
        cur.close()

#NEW UPDATE - UPDATE PASSWORD 2

@app.route('/update_password/<int:password_id>', methods=['POST'])
def update_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    key_id = request.form.get('key_id')
    site = request.form.get('site')
    login_name = request.form.get('login_name')
    password = request.form.get('passwords')
    title = request.form.get('title')

    # Check for required fields
    if not site or not login_name or not password:
        return "Required fields are missing", 400

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Fetch the encryption key based on key_id
        cur.execute("SELECT `key`, key_name FROM `keys` WHERE key_id = %s", (key_id,))
        key_record = cur.fetchone()

        if not key_record:
            print(f"Encryption key not found for key_id {key_id}")
            return jsonify({'message': 'Encryption key not found'}), 404

        encryption_key = key_record['key']
        key_name = key_record['key_name']
        print(f"Using encryption key for key_id {key_id}, key_name {key_name}: {encryption_key}")

        # Encrypt the password
        fernet = Fernet(encryption_key.encode())
        encrypted_password = fernet.encrypt(password.encode()).decode()
        print(f"Encrypted password for password_id {password_id}: {encrypted_password}")

        # Update only if the password belongs to the logged-in user
        query = """
            UPDATE passwords
            JOIN `keys` ON passwords.key_id = `keys`.key_id
            JOIN accounts ON `keys`.id = accounts.Id
            SET passwords.key_id = %s,
                passwords.site = %s,
                passwords.login_name = %s,
                passwords.passwords = %s,
                passwords.title = %s
            WHERE passwords.password_id = %s AND accounts.Id = %s
        """
        cur.execute(query, (key_id, site, login_name, encrypted_password, title, password_id, user_id))
        mysql.connection.commit()
        print(f"Password updated successfully for password_id {password_id}")
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error updating password: {str(e)}")
        return jsonify({'message': f'Error updating password: {str(e)}'}), 500
    finally:
        cur.close()

    return redirect(url_for('passwordvault'))

@app.route('/delete_key/<int:key_id>', methods=['DELETE'])
def delete_key(key_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized access'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    try:
        # Ensure the key belongs to the logged-in user
        cur.execute("SELECT key_id FROM `keys` WHERE key_id = %s AND id = %s", (key_id, user_id))
        key = cur.fetchone()

        if not key:
            return jsonify({'success': False, 'message': 'Key not found or unauthorized'}), 404

        # Delete all associated passwords
        cur.execute("DELETE FROM passwords WHERE key_id = %s", (key_id,))

        # Delete the key itself
        cur.execute("DELETE FROM `keys` WHERE key_id = %s", (key_id,))

        mysql.connection.commit()
        return jsonify({'success': True, 'message': 'Key and associated data deleted successfully'}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(f"Error deleting key with key_id={key_id}: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred while deleting the key. Please try again.'}), 500
    finally:
        cur.close()