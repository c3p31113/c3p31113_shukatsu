## picoCTF勉強日記



今回からpicoCTFで勉強をしようと思います。まずはPracticeのBeginner picoMini 2022の問題から解いてみようと思います。runme.pyなど簡単すぎる問題に関しては今回は省きます。問題名の文字は見やすくしています。



#### PW Crack1



Pythonファイルと暗号化されたフラッグが含有されてるlevel1.flag.txt.encを用いて解く問題で、Pythonスクリプト内にパスワードが書かれていたのでPythonファイルをパワーシェルから実行してパスワードを入力すると、暗号化されていたlevel1.flag.txt.encが復号されて、picoCTF{545h\_r1ng1ng\_56891419}といった具合にフラッグが出ました。



python level1.py

Please enter correct password for flag: 691d

Welcome back... your flag, user:

picoCTF{545h\_r1ng1ng\_56891419}





#### PW Crack2



今回は少しだけ難易度が上がっていて、user\_pw == chr(0x64) + chr(0x65) + chr(0x37) + chr(0x36)となっていてパスワードは一筋縄では渡してくれないみたいですが、これはシンプルなASCII文字であって解読すると、de76となりました。これをパスワードに入力したら暗号ファイルが解読されて、picoCTF{tr45h\_51ng1ng\_489dea9a}が出ました。



python level2.py

Please enter correct password for flag: de76

Welcome back... your flag, user:

picoCTF{tr45h\_51ng1ng\_489dea9a}





#### HashingJobApp



今回は与えられたワードをもとにMD5キャッシュに変換していく事で問題が進み、解いていくたびに最終的にフラッグが出てくるといった問題でしたが、問題には時間制限があってしかもだいぶ時間制限も短かったので、MD%変換サイトで迅速に変換することで、フラッグを取得できました。







nc saturn.picoctf.net 64356

Please md5 hash the text between quotes, excluding the quotes: 'Americans'

Answer:

165813154207e6cacef030430ea09616

165813154207e6cacef030430ea09616

Correct.

Please md5 hash the text between quotes, excluding the quotes: 'a haunted house'

Answer:

ede833ae0b697454d64168e0e84cc730

ede833ae0b697454d64168e0e84cc730

Correct.

Please md5 hash the text between quotes, excluding the quotes: 'coconuts'

Answer:

78d1999482f432e9c229269151140542

78d1999482f432e9c229269151140542

Correct.

picoCTF{4ppl1c4710n\_r3c31v3d\_3eb82b73}





#### Glitch Cat



今回は以前の問題よりもシンプルで以前とは違ってハッシュ化などの処理は必要なく、出てきたASCII文字をテキストに変換して元の文字と合わせるだけでフラッグが取得できました。

nc saturn.picoctf.net 62717

'picoCTF{gl17ch\_m3\_n07\_' + chr(0x61) + chr(0x34) + chr(0x33) + chr(0x39) + chr(0x32) + chr(0x64) + chr(0x32) + chr(0x65) + '}'



# 　　　　　⇩



picoCTF{gl17ch\_m3\_n07\_a4392d2e}





#### fixme2.py



今回は壊れてるPythonコードを直す問題でした。以下に元のコードを貼ります。



import random







def str\_xor(secret, key):

    #extend key to secret length

    new\_key = key

    i = 0

    while len(new\_key) < len(secret):

        new\_key = new\_key + key\[i]

        i = (i + 1) % len(key)

    return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])





flag\_enc = chr(0x15) + chr(0x07) + chr(0x08) + chr(0x06) + chr(0x27) + chr(0x21) + chr(0x23) + chr(0x15) + chr(0x58) + chr(0x18) + chr(0x11) + chr(0x41) + chr(0x09) + chr(0x5f) + chr(0x1f) + chr(0x10) + chr(0x3b) + chr(0x1b) + chr(0x55) + chr(0x1a) + chr(0x34) + chr(0x5d) + chr(0x51) + chr(0x40) + chr(0x54) + chr(0x09) + chr(0x05) + chr(0x04) + chr(0x57) + chr(0x1b) + chr(0x11) + chr(0x31) + chr(0x0d) + chr(0x5f) + chr(0x05) + chr(0x40) + chr(0x04) + chr(0x0b) + chr(0x0d) + chr(0x0a) + chr(0x19)



 

flag = str\_xor(flag\_enc, 'enkidu')



\# Check that flag is not empty

if flag = "":

  print('String XOR encountered a problem, quitting.')

else:

  print('That is correct! Here\\'s your flag: ' + flag)



幸いなことにPythonは大学である程度なら勉強していたので、すぐに違和感に気づけました。最後のif分のイコール部分がでエラーが出てたので==に直したらファイルが実行されてThat is correct! Here's your flag: picoCTF{3qu4l1ty\_n0t\_4551gnm3nt\_f6a5aefc}と出ました。





#### fixme1.py



順序を間違えたかもですが、次はこの問題です。先ほど同様に以下にもとのコードを貼ります。









import random







def str\_xor(secret, key):

    #extend key to secret length

    new\_key = key

    i = 0

    while len(new\_key) < len(secret):

        new\_key = new\_key + key\[i]

        i = (i + 1) % len(key)

    return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])





flag\_enc = chr(0x15) + chr(0x07) + chr(0x08) + chr(0x06) + chr(0x27) + chr(0x21) + chr(0x23) + chr(0x15) + chr(0x5a) + chr(0x07) + chr(0x00) + chr(0x46) + chr(0x0b) + chr(0x1a) + chr(0x5a) + chr(0x1d) + chr(0x1d) + chr(0x2a) + chr(0x06) + chr(0x1c) + chr(0x5a) + chr(0x5c) + chr(0x55) + chr(0x40) + chr(0x3a) + chr(0x58) + chr(0x0a) + chr(0x5d) + chr(0x53) + chr(0x43) + chr(0x06) + chr(0x56) + chr(0x0d) + chr(0x14)



 

flag = str\_xor(flag\_enc, 'enkidu')

 

  print('That is correct! Here\\'s your flag: ' + flag)





わかりづらいかもしれませんが、ただのインデントミスなのでprintの前の空白を消してインデントを揃えたらThat is correct! Here's your flag: picoCTF{1nd3nt1ty\_cr1515\_6a476c8f}と出ました。





#### convertme.py



ダウンロードしてファイルを実行すると問題が出されます。もし 64 が 10進数（decimal base）なら、それは 2進数（binary base）で何ですか？といった問題が出たので調べて答えを入力したら、フラッグが出ました。



python convertme.py

If 64 is in decimal base, what is it in binary base?

Answer: 1000000

That is correct! Here's your flag: picoCTF{4ll\_y0ur\_b4535\_762f748e}





#### Codebook



今回はPythonファイルとテキストファイルを同じディレクトリにいれてダウンロードして実行するだけでした。



import random

import sys







def str\_xor(secret, key):

    #extend key to secret length

    new\_key = key

    i = 0

    while len(new\_key) < len(secret):

        new\_key = new\_key + key\[i]

        i = (i + 1) % len(key)

    return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])





flag\_enc = chr(0x13) + chr(0x01) + chr(0x17) + chr(0x07) + chr(0x2c) + chr(0x3a) + chr(0x2f) + chr(0x1a) + chr(0x0d) + chr(0x53) + chr(0x0c) + chr(0x47) + chr(0x0a) + chr(0x5f) + chr(0x5e) + chr(0x02) + chr(0x3e) + chr(0x5a) + chr(0x56) + chr(0x5d) + chr(0x45) + chr(0x5d) + chr(0x58) + chr(0x31) + chr(0x58) + chr(0x58) + chr(0x59) + chr(0x02) + chr(0x51) + chr(0x4c) + chr(0x5a) + chr(0x0c) + chr(0x13)







def print\_flag():

  try:

    codebook = open('codebook.txt', 'r').read()

 

    password = codebook\[4] + codebook\[14] + codebook\[13] + codebook\[14] +\\

               codebook\[23]+ codebook\[25] + codebook\[16] + codebook\[0]  +\\

               codebook\[25]

 

    flag = str\_xor(flag\_enc, password)

    print(flag)

  except FileNotFoundError:

    print('Couldn\\'t find codebook.txt. Did you download that file into the same directory as this script?')







def main():

  print\_flag()







if \_\_name\_\_ == "\_\_main\_\_":

  main()

以上がもとのコードです。



python code.py

picoCTF{c0d3b00k\_455157\_197a982c}





#### Serpentine



今回もPythonスクリプトの問題ですが、今までとは違って少し複雑な問題となっています。





import random

import sys







def str\_xor(secret, key):

    #extend key to secret length

    new\_key = key

    i = 0

    while len(new\_key) < len(secret):

        new\_key = new\_key + key\[i]

        i = (i + 1) % len(key)

    return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])





flag\_enc = chr(0x15) + chr(0x07) + chr(0x08) + chr(0x06) + chr(0x27) + chr(0x21) + chr(0x23) + chr(0x15) + chr(0x5c) + chr(0x01) + chr(0x57) + chr(0x2a) + chr(0x17) + chr(0x5e) + chr(0x5f) + chr(0x0d) + chr(0x3b) + chr(0x19) + chr(0x56) + chr(0x5b) + chr(0x5e) + chr(0x36) + chr(0x53) + chr(0x07) + chr(0x51) + chr(0x18) + chr(0x58) + chr(0x05) + chr(0x57) + chr(0x11) + chr(0x3a) + chr(0x0f) + chr(0x0a) + chr(0x5b) + chr(0x57) + chr(0x41) + chr(0x55) + chr(0x0c) + chr(0x59) + chr(0x14)





def print\_flag():

  flag = str\_xor(flag\_enc, 'enkidu')

  print(flag)





def print\_encouragement():

  encouragements = \['You can do it!', 'Keep it up!',

                    'Look how far you\\'ve come!']

  choice = random.choice(range(0, len(encouragements)))

  print('\\n-----------------------------------------------------')

  print(encouragements\[choice])

  print('-----------------------------------------------------\\n\\n')







def main():



  print(

'''

    Y

  .-^-.

 /     \\      .- ~ ~ -.

()     ()    /   \_ \_   `.                     \_ \_ \_

 \\\_   \_/    /  /     \\   \\                . ~  \_ \_  ~ .

   | |     /  /       \\   \\             .' .~       ~-. `.

   | |    /  /         )   )           /  /             `.`.

   \\ \\\_ \_/  /         /   /           /  /                `'

    \\\_ \_ \_.'         /   /           (  (

                    /   /             \\  \\\\

                   /   /               \\  \\\\

                  /   /                 )  )

                 (   (                 /  /

                  `.  `.             .'  /

                    `.   ~ - - - - ~   .'

                       ~ . \_ \_ \_ \_ . ~

'''

  )

  print('Welcome to the serpentine encourager!\\n\\n')

 

  while True:

    print('a) Print encouragement')

    print('b) Print flag')

    print('c) Quit\\n')

    choice = input('What would you like to do? (a/b/c) ')

 

    if choice == 'a':

      print\_encouragement()

 

    elif choice == 'b':

      print('\\nOops! I must have misplaced the print\_flag function! Check my source code!\\n\\n')

 

    elif choice == 'c':

      sys.exit(0)

 

    else:

      print('\\nI did not understand "' + choice + '", input only "a", "b" or "c"\\n\\n')







if \_\_name\_\_ == "\_\_main\_\_":

  main()



以上のコードが元のコードです。このままだとa,b,cどれを入力しても、フラッグは出力されません。なので一部コードを書き替える必要があります。なので

elif choice == 'b':
print('\\nOops! I must have misplaced the print\_flag function! Check my source code!\\n\\n')

の部分のprint文を消して、

flag = str\_xor(flag\_enc, 'enkidu')
print(flag)

を代わりにもってくればフラッグが出力されます。結構Python勉強してないとなかなか気づけないかもしれないので、こういう問題はAIに任せて解説してもらって勉強するのもありな気がしました。



#### PW Crack 4



今回は今までのパスワードクラック系よりもさらに複雑になってたので、調べたりしました。でも結果的にいちばん楽な解法はスクリプトを書き換えて総当たり(パスワード100個)でパスワードを入力していって答えをだす方式を選びました。以下がへんこうまえのコードです。



import hashlib



\### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################

def str\_xor(secret, key):

&nbsp;   #extend key to secret length

&nbsp;   new\_key = key

&nbsp;   i = 0

&nbsp;   while len(new\_key) < len(secret):

&nbsp;       new\_key = new\_key + key\[i]

&nbsp;       i = (i + 1) % len(key)        

&nbsp;   return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])

\###############################################################################



flag\_enc = open('level4.flag.txt.enc', 'rb').read()

correct\_pw\_hash = open('level4.hash.bin', 'rb').read()





def hash\_pw(pw\_str):

&nbsp;   pw\_bytes = bytearray()

&nbsp;   pw\_bytes.extend(pw\_str.encode())

&nbsp;   m = hashlib.md5()

&nbsp;   m.update(pw\_bytes)

&nbsp;   return m.digest()





def level\_4\_pw\_check():

&nbsp;   user\_pw = input("Please enter correct password for flag: ")

&nbsp;   user\_pw\_hash = hash\_pw(user\_pw)

&nbsp;   

&nbsp;   if( user\_pw\_hash == correct\_pw\_hash ):

&nbsp;       print("Welcome back... your flag, user:")

&nbsp;       decryption = str\_xor(flag\_enc.decode(), user\_pw)

&nbsp;       print(decryption)

&nbsp;       return

&nbsp;   print("That password is incorrect")







level\_4\_pw\_check()







\# The strings below are 100 possibilities for the correct password. 

\#   (Only 1 is correct)

pos\_pw\_list = \["6288", "6152", "4c7a", "b722", "9a6e", "6717", "4389", "1a28", "37ac", "de4f", "eb28", "351b", "3d58", "948b", "231b", "973a", "a087", "384a", "6d3c", "9065", "725c", "fd60", "4d4f", "6a60", "7213", "93e6", "8c54", "537d", "a1da", "c718", "9de8", "ebe3", "f1c5", "a0bf", "ccab", "4938", "8f97", "3327", "8029", "41f2", "a04f", "c7f9", "b453", "90a5", "25dc", "26b0", "cb42", "de89", "2451", "1dd3", "7f2c", "8919", "f3a9", "b88f", "eaa8", "776a", "6236", "98f5", "492b", "507d", "18e8", "cfb5", "76fd", "6017", "30de", "bbae", "354e", "4013", "3153", "e9cc", "cba9", "25ea", "c06c", "a166", "faf1", "2264", "2179", "cf30", "4b47", "3446", "b213", "88a3", "6253", "db88", "c38c", "a48c", "3e4f", "7208", "9dcb", "fc77", "e2cf", "8552", "f6f8", "7079", "42ef", "391e", "8a6d", "2154", "d964", "49ec"]


これに



for pw in pos\_pw\_list:

&nbsp;   if hash\_pw(pw) == correct\_pw\_hash:

&nbsp;       print("Correct password found:", pw)

&nbsp;       print("Flag:", str\_xor(flag\_enc.decode(), pw))

&nbsp;       break

このようにループでパスワードを入力する関数を組むことで答えが出ました。



python level4.py

Please enter correct password for flag:

That password is incorrect

Correct password found: 973a

Flag: picoCTF{fl45h\_5pr1ng1ng\_ae0fb77c}





なんだか正規の解法ではない気がして調べたのですが、どうやらこれが正規の解法らしいです。



#### PW Crack 5



4の進化版で今度はパスワードリスト内のパスワードの候補が大幅に増えています。それと今回はコード内にパスワード候補が書かれてるのではなく、dictionary.txtという、いわゆる辞書があったのでそれを参照する形でブルートフォースを仕掛ければいいかなと思っています。



import hashlib



\### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################

def str\_xor(secret, key):

&nbsp;   #extend key to secret length

&nbsp;   new\_key = key

&nbsp;   i = 0

&nbsp;   while len(new\_key) < len(secret):

&nbsp;       new\_key = new\_key + key\[i]

&nbsp;       i = (i + 1) % len(key)        

&nbsp;   return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])

\###############################################################################



flag\_enc = open('level5.flag.txt.enc', 'rb').read()

correct\_pw\_hash = open('level5.hash.bin', 'rb').read()





def hash\_pw(pw\_str):

&nbsp;   pw\_bytes = bytearray()

&nbsp;   pw\_bytes.extend(pw\_str.encode())

&nbsp;   m = hashlib.md5()

&nbsp;   m.update(pw\_bytes)

&nbsp;   return m.digest()





def level\_5\_pw\_check():

&nbsp;   user\_pw = input("Please enter correct password for flag: ")

&nbsp;   user\_pw\_hash = hash\_pw(user\_pw)

&nbsp;   

&nbsp;   if( user\_pw\_hash == correct\_pw\_hash ):

&nbsp;       print("Welcome back... your flag, user:")

&nbsp;       decryption = str\_xor(flag\_enc.decode(), user\_pw)

&nbsp;       print(decryption)

&nbsp;       return

&nbsp;   print("That password is incorrect")







level\_5\_pw\_check()



以上がもとのコードです。以下のコードを末尾に追加しました。





with open("dictionary.txt", "r", encoding="utf-8", errors="ignore") as f:

&nbsp;   for line in f:

&nbsp;       pw = line.strip()

&nbsp;       if hash\_pw(pw) == correct\_pw\_hash:

&nbsp;           print("Correct password found:", pw)

&nbsp;           print("Flag:", str\_xor(flag\_enc.decode(), pw))

&nbsp;           break



dictionary.txtを参照し、UTFでエンコーディングしforループで繰り返すコードです。6万個以上もパスワードがあったので時間かかるかと思ってましたが以外にも2秒くらいで結果が返ってきました。以下が出力です。



python level5.py

Please enter correct password for flag:

That password is incorrect

Correct password found: 9581

Flag: picoCTF{h45h\_sl1ng1ng\_36e992a6}



これぞパスワードクラッキングって感じで楽しめました。



#### PW Crack 3



順序がばらばらで3が最後になってしまいました。でもやってることはほぼ4と変わらないです。以下に元のコードを貼ります。



import hashlib



\### THIS FUNCTION WILL NOT HELP YOU FIND THE FLAG --LT ########################

def str\_xor(secret, key):

&nbsp;   #extend key to secret length

&nbsp;   new\_key = key

&nbsp;   i = 0

&nbsp;   while len(new\_key) < len(secret):

&nbsp;       new\_key = new\_key + key\[i]

&nbsp;       i = (i + 1) % len(key)        

&nbsp;   return "".join(\[chr(ord(secret\_c) ^ ord(new\_key\_c)) for (secret\_c,new\_key\_c) in zip(secret,new\_key)])

\###############################################################################



flag\_enc = open('level3.flag.txt.enc', 'rb').read()

correct\_pw\_hash = open('level3.hash.bin', 'rb').read()





def hash\_pw(pw\_str):

&nbsp;   pw\_bytes = bytearray()

&nbsp;   pw\_bytes.extend(pw\_str.encode())

&nbsp;   m = hashlib.md5()

&nbsp;   m.update(pw\_bytes)

&nbsp;   return m.digest()





def level\_3\_pw\_check():

&nbsp;   user\_pw = input("Please enter correct password for flag: ")

&nbsp;   user\_pw\_hash = hash\_pw(user\_pw)

&nbsp;   

&nbsp;   if( user\_pw\_hash == correct\_pw\_hash ):

&nbsp;       print("Welcome back... your flag, user:")

&nbsp;       decryption = str\_xor(flag\_enc.decode(), user\_pw)

&nbsp;       print(decryption)

&nbsp;       return

&nbsp;   print("That password is incorrect")







level\_3\_pw\_check()





\# The strings below are 7 possibilities for the correct password. 

\#   (Only 1 is correct)

pos\_pw\_list = \["8799", "d3ab", "1ea2", "acaf", "2295", "a9de", "6f3d"]



以上ですが、今回も同様に

for pw in pos\_pw\_list:

&nbsp;   if hash\_pw(pw) == correct\_pw\_hash:

&nbsp;       print("Correct password found:", pw)

&nbsp;       print("Flag:", str\_xor(flag\_enc.decode(), pw))

&nbsp;       break

上記のコードを末尾に付け足したらフラッグが出ました。

python level3.py

Please enter correct password for flag:

That password is incorrect

Correct password found: 2295

Flag: picoCTF{m45h\_fl1ng1ng\_6f98a49f}







以上でBeginner picoMini 2022の問題は終わりです。CpawCTFよりも難易度は低めでしたが、でもちゃんとやってる感がすごくてどの問題も楽しみながら学習できました。

