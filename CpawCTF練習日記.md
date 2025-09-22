# CpawCTF練習日記



#### Q6.\[Crypto] Classical Cipher

10pt



暗号には大きく分けて、古典暗号と現代暗号の2種類があります。特に古典暗号では、古代ローマの軍事的指導者ガイウス・ユリウス・カエサル（英語読みでシーザー）が初めて使ったことから、名称がついたシーザー暗号が有名です。これは3文字分アルファベットをずらすという単一換字式暗号の一つです。次の暗号文は、このシーザー暗号を用いて暗号化しました。暗号文を解読してフラグを手にいれましょう。



暗号文: fsdz{Fdhvdu\_flskhu\_lv\_fodvvlfdo\_flskhu}





abcdefghijklmnopqrstuvwxyz



i

cpaw{Caesar\_cipher\_is\_classical\_cipher}



問題文にある通り、3文字戻った文字を当てはめていったら答えが出せました。







#### Q7.\[Reversing] Can you execute ?

10pt



拡張子がないファイルを貰ってこのファイルを実行しろと言われたが、どうしたら実行出来るのだろうか。

この場合、UnixやLinuxのとあるコマンドを使ってファイルの種類を調べて、適切なOSで実行するのが一般的らしいが…

問題ファイル： exec\_me





ステップ1：ファイルの正体を暴く



PowerShellでまずはcd C:\\Users\\user\_name\\Downloadsに移動し、WSL2のKali Linuxを起動





file exec\_me





このコマンドで得られた結果は：





ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2





つまり、これはLinux用の実行可能バイナリ。拡張子がなくても、ちゃんと「実行できるファイル」であることがわかりました。





 ステップ2：実行権限の確認と実行





ls -l exec\_me





すでに `-rwxrwxrwx` というフル権限が付与されていたので、すぐに実行可能であることがわかりました。





./exec\_me





実行結果➡cpaw{Do\_you\_know\_ELF\_file?}



実行すると、フラッグが表示され。ここで「実行できるか？」という問いに対して、自分の手で答えを出せた瞬間でした。







気づきと学び



\- 拡張子に頼らず、\*\*中身を調べる力\*\*が重要

\- `file`, `chmod`, `ls`, `./` などの基本コマンドが強力な武器になる





#### Q8.\[Misc] Can you open this file ?

10pt



このファイルを開きたいが拡張子がないので、どのような種類のファイルで、どのアプリケーションで開けば良いかわからない。

どうにかして、この拡張子がないこのファイルの種類を特定し、どのアプリケーションで開くか調べてくれ。

問題ファイル： open\_me



前回同様に拡張子なしです。見た目では何もわかりません。 でも file open\_me と打ってみると、そこには「Microsoft Office Word」の文字がありました。 そこからはいろいろ試行錯誤を繰り返し、ある時に.docと試しに拡張子をつけてみたところ開くことができました。 中身は短い文書だったけど、拡張子がない＝中身が不明ではないということを、また一つ実感できました。



cpaw{Th1s\_f1le\_c0uld\_be\_0p3n3d}





#### Q9.\[Web] HTML Page

10pt



HTML(Hyper Text Markup Language)は、Webサイトを記述するための言語です。

ページに表示されている部分以外にも、ページをより良くみせるためのデータが含まれています。

次のWebサイトからフラグを探して下さい。

http://q9.ctf.cpaw.site

今回はサイトに隠れたフラッグを見つける問題ですが、とりあえず開発者ツールで調査してみたところ<p><font color="#fafafa">Do you read description of this page?</font></p>というコードを発見フォントカラーがページと同化していました。ですが、そこからは特に何も見つからないかと思ったら上部の方に<meta name="description" content="flag is cpaw{9216ddf84851f15a46662eb04759d2bebacac666}">と記載がありました。今回は比較的今までの問題に比べたら解きやすかったです。





#### Q10.\[Forensics] River

10pt



JPEGという画像ファイルのフォーマットでは、撮影時の日時、使われたカメラ、位置情報など様々な情報(Exif情報)が付加されることがあるらしい。

この情報から、写真に写っている川の名前を特定して欲しい。

問題ファイル： river.jpg



FLAGの形式は、"cpaw{river\_name}"

例：隅田川 → cpaw{sumidagawa}



exif情報の特定の仕方はわからなかったのでとりあえず手探りでいろいろやってみました。まずはfileコマンドで試しました。

file river.jpg

river.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: \[TIFF image data, big-endian, direntries=10, manufacturer=Sony, model=SO-01G, orientation=upper-left, xresolution=148, yresolution=156, resolutionunit=2, software=23.1.B.1.160\_6\_f1000010, datetime=2015:09:14 12:50:38, GPS-Data], baseline, precision 8, 3840x2160, components 3

Exifが埋め込まれてるってことはわかりましたが特に有力な情報は得られませんでした。そこでコマンドを調べた結果exiftoolというコマンドがあるらしいのでそれで実行してみました。



&nbsp;exiftool river.jpg

ExifTool Version Number         : 13.25

File Name                       : river.jpg

Directory                       : .

File Size                       : 424 kB

File Modification Date/Time     : 2025:09:19 22:35:35+09:00

File Access Date/Time           : 2025:09:19 22:35:35+09:00

File Inode Change Date/Time     : 2025:09:19 22:35:35+09:00

File Permissions                : -rwxrwxrwx

File Type                       : JPEG

File Type Extension             : jpg

MIME Type                       : image/jpeg

JFIF Version                    : 1.01

Exif Byte Order                 : Big-endian (Motorola, MM)

Make                            : Sony

Camera Model Name               : SO-01G

Orientation                     : Horizontal (normal)

X Resolution                    : 72

Y Resolution                    : 72

Resolution Unit                 : inches

Software                        : 23.1.B.1.160\_6\_f1000010

Modify Date                     : 2015:09:14 12:50:38

Exposure Time                   : 1/2000

F Number                        : 2.0

ISO                             : 50

Exif Version                    : 0220

Date/Time Original              : 2015:09:14 12:50:38

Create Date                     : 2015:09:14 12:50:38

Components Configuration        : Y, Cb, Cr, -

Shutter Speed Value             : 1/1992

Exposure Compensation           : 0

Metering Mode                   : Multi-segment

Light Source                    : Unknown

Flash                           : Off, Did not fire

Focal Length                    : 4.6 mm

Sub Sec Time                    : 190234

Sub Sec Time Original           : 190234

Sub Sec Time Digitized          : 190234

Flashpix Version                : 0100

Color Space                     : sRGB

Exif Image Width                : 3840

Exif Image Height               : 2160

Custom Rendered                 : Normal

Exposure Mode                   : Auto

White Balance                   : Auto

Digital Zoom Ratio              : 1

Scene Capture Type              : Landscape

Subject Distance Range          : Unknown

GPS Version ID                  : 2.3.0.0

GPS Latitude Ref                : North

GPS Longitude Ref               : East

XMP Toolkit                     : XMP Core 5.4.0

Creator Tool                    : 23.1.B.1.160\_6\_f1000010

Current IPTC Digest             : d5bc65b4a8aa881aa3cbcb4c82d92707

Coded Character Set             : UTF8

Application Record Version      : 2

Digital Creation Time           : 12:50:38

Digital Creation Date           : 2015:09:14

Date Created                    : 2015:09:14

Time Created                    : 12:50:38

IPTC Digest                     : d5bc65b4a8aa881aa3cbcb4c82d92707

Profile CMM Type                : Linotronic

Profile Version                 : 2.1.0

Profile Class                   : Display Device Profile

Color Space Data                : RGB

Profile Connection Space        : XYZ

Profile Date Time               : 1998:02:09 06:49:00

Profile File Signature          : acsp

Primary Platform                : Microsoft Corporation

CMM Flags                       : Not Embedded, Independent

Device Manufacturer             : Hewlett-Packard

Device Model                    : sRGB

Device Attributes               : Reflective, Glossy, Positive, Color

Rendering Intent                : Perceptual

Connection Space Illuminant     : 0.9642 1 0.82491

Profile Creator                 : Hewlett-Packard

Profile ID                      : 0

Profile Copyright               : Copyright (c) 1998 Hewlett-Packard Company

Profile Description             : sRGB IEC61966-2.1

Media White Point               : 0.95045 1 1.08905

Media Black Point               : 0 0 0

Red Matrix Column               : 0.43607 0.22249 0.01392

Green Matrix Column             : 0.38515 0.71687 0.09708

Blue Matrix Column              : 0.14307 0.06061 0.7141

Device Mfg Desc                 : IEC http://www.iec.ch

Device Model Desc               : IEC 61966-2.1 Default RGB colour space - sRGB

Viewing Cond Desc               : Reference Viewing Condition in IEC61966-2.1

Viewing Cond Illuminant         : 19.6445 20.3718 16.8089

Viewing Cond Surround           : 3.92889 4.07439 3.36179

Viewing Cond Illuminant Type    : D50

Luminance                       : 76.03647 80 87.12462

Measurement Observer            : CIE 1931

Measurement Backing             : 0 0 0

Measurement Geometry            : Unknown

Measurement Flare               : 0.999%

Measurement Illuminant          : D65

Technology                      : Cathode Ray Tube Display

Red Tone Reproduction Curve     : (Binary data 2060 bytes, use -b option to extract)

Green Tone Reproduction Curve   : (Binary data 2060 bytes, use -b option to extract)

Blue Tone Reproduction Curve    : (Binary data 2060 bytes, use -b option to extract)

Image Width                     : 3840

Image Height                    : 2160

Encoding Process                : Baseline DCT, Huffman coding

Bits Per Sample                 : 8

Color Components                : 3

Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)

Aperture                        : 2.0

Image Size                      : 3840x2160

Megapixels                      : 8.3

Shutter Speed                   : 1/2000

Create Date                     : 2015:09:14 12:50:38.190234

Date/Time Original              : 2015:09:14 12:50:38.190234

Modify Date                     : 2015:09:14 12:50:38.190234

GPS Latitude                    : 31 deg 35' 2.76" N

GPS Longitude                   : 130 deg 32' 51.73" E

Date/Time Created               : 2015:09:14 12:50:38

Digital Creation Date/Time      : 2015:09:14 12:50:38

Focal Length                    : 4.6 mm

GPS Position                    : 31 deg 35' 2.76" N, 130 deg 32' 51.73" E

Light Value                     : 14.0

以上の通り莫大な情報が出ましたが川に関する記載がありませんでした。なのでGPS LatitudeとGPS Longitudeという部分をそのままグーグルマップで検索してみても何もヒットしませんでした。なので色々ちょうさをしたらどうやらここで出ている緯度と経度はDMS形式といういわば度・分・秒で表されてる形式らしく、グーグルマップなどで検索をかけるには10進数にへんかんする必要があるみたいでした。なので10進数に変換したら緯度が31.5841で経度が130.5477となりました。これで検索を掛けたら鹿児島県の甲突川という場所だという事がわかりました。フラッグはcpaw{koutsukigawa}でした。





#### Q11.\[Network]pcap

10pt



ネットワークを流れているデータはパケットというデータの塊です。

それを保存したのがpcapファイルです。

pcapファイルを開いて、ネットワークにふれてみましょう！

pcapファイル

とりあえず見たことない拡張子だったのでfileコマンドで

見てみました。



file network10.pcap

network10.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)

特に有力な結果は得られずでした。pcapファイルはどうやらwiresharkで開けるらしいので開いてみたら二つほどデータがあって、見てみるとcpaw{gochi\_usa\_kami}との記載がありました。どうやらICMPパケットの中にASCIIとしてフラグがうめこまれていたみたいです。CTFではよくあるらしいので勉強になりました。





Q12.\[Crypto]HashHashHash!

10pt



ハッシュ関数とは、値を入れたら絶対にもとに戻せないハッシュ値と呼ばれる値が返ってくる関数です。

ですが、レインボーテーブルなどでいくつかのハッシュ関数は元に戻せてしまう時代になってしまいました。

以下のSHA1というハッシュ関数で作られたハッシュ値を元に戻してみてください！（ヒント：googleで検索）



e4c6bced9edff99746401bd077afa92860f83de3



フラグは

cpaw{ハッシュを戻した値}

です。

ハッシュ関数はきいたことありますが特定の方法まではわからなかったので、ヒントにも書いてある通りハッシュ関数をそのまま検索したらSHA-1ハッシュをリバースできるさいとがあったので、そのまま文字を入力しました。そしたらShalという文字に変換されたのでcpaw{Shal}が正解でした。今回は結構簡単でしたが、SHA-1をリバースできるなんて知らなかったので新たな学びになりました。





#### Q14.\[PPC]並べ替えろ!

10pt



下にある配列の中身を大きい順に並べ替えて、くっつけてcpaw{並べ替えた後の値}をフラグとして提出してください。

例：もし配列｛1,5,3,2｝っていう配列があったら、大きい順に並べ替えると｛5,3,2,1}となります。

そして、フラグはcpaw{5321}となります。

同じようにやってみましょう（ただし量が多いので、ソートするプログラムを書いたほうがいいですよ！）





\[15,1,93,52,66,31,87,0,42,77,46,24,99,10,19,36,27,4,58,76,2,81,50,102,33,94,20,14,80,82,49,41,12,143,121,7,111,100,60,55,108,34,150,103,109,130,25,54,57,159,136,110,3,167,119,72,18,151,105,171,160,144,85,201,193,188,190,146,210,211,63,207]





今回はソートするプログラムをかいた方がいいとの事なので、Pythonでプログラムを作ってみました。





nums = \[15,1,93,52,66,31,87,0,42,77,46,24,99,10,19,36,27,4,58,76,2,81,50,102,33,94,20,14,80,82,49,41,12,143,121,7,111,100,60,55,108,34,150,103,109,130,25,54,57,159,136,110,3,167,119,72,18,151,105,171,160,144,85,201,193,188,190,146,210,211,63,207]



\# 大きい順に並べ替え

sorted\_nums = sorted(nums, reverse=True)



\# 数字を文字列に変換して連結

joined = ''.join(str(n) for n in sorted\_nums)



\# フラグ形式に整形

flag = f"cpaw{{{joined}}}"



print(flag)



結果はcpaw{2112102072011931901881711671601591511501461441431361301211191111101091081051031021009994938785828180777672666360585755545250494642413634333127252420191815141210743210}となりました。ロジックはシンプルですが、CTFでコードを書く場面があるのは知らなかったので勉強になりました。


以上がLevel1の問題集でしたが、右も左もわからなかったので、すべてが新鮮でした。Kali Linuxを使うだけでなくコーディング作業があったりグーグルマップを使ったり、外部のサイトを使ったりと色々な手段を駆使して使う楽しさや難しさがあって、CTFって非常に面白いんだなと思い、俄然興味ややる気が湧いてきました。





#### Q13.\[Stego]隠されたフラグ

100pt



以下の画像には、実はフラグが隠されています。

目を凝らして画像を見てみると、すみっこに何かが…!!!!

フラグの形式はcpaw{\*\*\*}です。フラグは小文字にしてください。

stego100.jpg



画像を見てみたら右端に黒い点や棒があって見た目的にモールス信号みたいだったので変換してみました。



&nbsp;-.-. .--. .- .-- .... .. -.. -.. . -. ..--.- -- . ... ... .- --. . ---... -.--.-

↓



HIDDEN\_MESSAGE:)



といった感じになりました。なので答えはcpaw{hidden\_message:)}



気づいたら深夜になっていたので１日目の学習はここまでにします。


#### Q15.\[Web] Redirect

100pt



このURLにアクセスすると、他のページにリダイレクトされてしまうらしい。

果たしてリダイレクトはどのようにされているのだろうか…

http://q15.ctf.cpaw.site



どうしたらいいか全くわからなかったので、調べたらLinuxや他のOSで利用可能なコマンドラインツールで、HTTPやFTPなどのプロトコルを使用してデータを送受信するためのcurlコマンドというコマンドを使用するのがいいのかと思い、実行してみた結果



curl -I http://q15.ctf.cpaw.site



HTTP/1.1 302 Found

Server: nginx

Date: Sat, 20 Sep 2025 11:54:47 GMT

Content-Type: text/html; charset=UTF-8

Connection: keep-alive

X-Flag: cpaw{4re\_y0u\_1ook1ng\_http\_h3ader?}

Location: http://q9.ctf.cpaw.site

以上の情報が得られました。よくみたらX-Flag: cpaw{4re\_y0u\_1ook1ng\_http\_h3ader?}という記述があり、あっさりフラッグが見つかりました。今回はヘッダだけを確認するコマンドで見つかりました。さらに後々わかったのですが、これ開発者ツールでヘッダを見てもちゃんとフラッグが書いてありました。





#### Q16.\[Network+Forensic]HTTP Traffic

100pt



HTTPはWebページを閲覧する時に使われるネットワークプロトコルである。

ここに、とあるWebページを見た時のパケットキャプチャファイルがある。

このファイルから、見ていたページを復元して欲しい。

http\_traffic.pcap



このファイルは以前wiresharkで開けたので、今回も同様にwiresharkで開いて見ました。ですがこれ以降本当に行き詰ってしまったのでヒントを調べてみました。ヒントを参考にしながらhttpでソートをかけてhttpのパケットだけに絞ってみました。そこからも何をすればよいかわからず、また調べてみることにしました。どうやらhttpオブジェクトをエクスポートしてダウンロードし、ダウンロードしたファイルの中でも拡張子がないファイル（network100やnetwork100(1)）などがあり、拡張子をhtmlにして開くと、CSSやJavaScriptが読み込まれていないページが開かれました。開発者ツールで調査してみたところ、どうやらCSSやJavScriptを適切なディレクトリに移さないといけないらしく、

cssというフォルダとjsとimgというフォルダを作り、そこに各ファイルを格納したところ、正常にページが開かれて、JavaScriptも機能していました、そしてページのボタンを押すとcpaw{Y0u\_r3st0r3d\_7his\_p4ge}が表示されました。今回は結構タスクが複雑で、適切なディレクトリにファイルを移すこと以外は全くわからないことだらけだったので、こんなやり方もあるのかと勉強になりました。ただ、今回は結構ヒントに頼ってしまったのでこのやり方や考え方はちゃんと覚えようと思いました。







#### Q17.\[Recon]Who am I ?

100pt



僕(twitter:@porisuteru)はスペシャルフォース2をプレイしています。

とても面白いゲームです。

このゲームでは、僕は何と言う名前でプレイしているでしょう！

フラグはcpaw{僕のゲームアカウント名}です。



最初この問題を見た時はそんなことできるのか、、、って思いましたが、以外にもシンプルで、アカウント名の過去ポストを遡ったらスコアボードのスクリーンショットが載ってるポストがあって、そこに記載されていました。なのでcpaw{parock}となりました。







#### Q18.\[Forensic]leaf in forest

100pt



このファイルの中にはフラグがあります。探してください。

フラグはすべて小文字です！



file



今回は一切ヒントがないので、何をしたらよいのやらといった感じですが、まずは手当たり次第にいろいろやってみようと思います。とりあえずfileコマンドで見てみました。

file misc100

misc100: pcap capture file, microsecond ts (little-endian) - version 0.0 (linktype#1768711542, capture length 1869357413)

pcapファイルとのことなのでwiresharkで開こうとしたのですが、どうやら.pcapに拡張子を変えてもサポートされてない形式だと表示され、wiresharkでは開けませんでした。そこから迷走し、ふと拡張子をhtmlに変えてHTMLファイルとして開いたとき、少しの文字化けとあとは大量のlovelive!の文字があっていわゆるこれがleaf in forestの名前の通り森であってこの中からノイズを除去して葉っぱを見つけるのだと思いましたが、どうやってこの大量のノイズを取り除けるのか考えて調べてみました。どうやらkali linuxを使うらしく、stringsコマンドで直接ファイルの中身を見てみたら先ほど同様大量のlovelive!の文字が出たのでノイズを除去するために以下のコマンドを実行しました。



strings misc100 | tr -d 'lovelive!'

CCCPPPAAAWWW{{{MMMGGGRRREEEPPP}}}

こうするとlovelive!の文字が除去されてフラッグの文字だけが残りました。なので答えはcpaw{mgrep}です。今回もけっこう調べて時間をかけて色々試したのですがfileコマンドで見た情報が実は罠でpcapに偽装されてたなんて思いもしなかったので、出た情報を信じたうえで考えるのはやめようと思いました。今回の演習では、根本を疑ってみるのも大切だという事が学べました。これがゼロトラストって概念なのでしょうか？わかりませんが、、、







#### Q19.\[Misc]Image!

100pt



Find the flag in this zip file.

file



今回も全くヒントなしです。とりあえずファイルをくまなく見て回ってみました。そうするとthumbnail.pngというファイルがあり、その画像にはflag is cpaw{■■■}と書いてあり肝心のこたえの部分が黒塗りされてました。でもこれ以降画像ソフトを使って黒塗りの部分の明度や彩度をいじってみたりと色々してみましたが特に進展はなかったです。そこで一旦thumbnail.pngからは離れて別ファイルを見てみました。とりあえず同封されてるXMLファイルを開いて中身をみてみることにしました。しかし片っ端から見てたらあまりにも時間がかかってしまうと思ったので、content.xml や styles.xml、META-INF/manifest.xmlのファイルが気になったのでどんなものかと調べてみたらどうやらこれらのファイルはOpenDocument形式のファイルに必ず入っているものらしく、試しに content.xml をテキストエディタで開いてみたら

<draw:text-box> <text:p text:style-name="P2"> <text:span text:style-name="T1">It\_is\_fun\_\_isn't\_it?</text:span> </text:p> </draw:text-box>

という記述がありもしかして黒塗りの部分の文字はIt\_is\_fun\_\_isn't\_it?なのではないかと推測しました。予想は当たっていてcpaw{It\_is\_fun\_\_isn't\_it?}が答えでした。黒塗りの下に隠されていたはずのテキストが、そのままXMLの中に残っていたなんて思いもしませんでした。黒塗りはただの図形オブジェクトで、データ自体は消えていなかったらしいです。ついでに他の人がどんな風に解いたかも気になって調べてみたのですが、LibraOffice Drawを使ってファイルを開くとどうやら画像が編集できるようになるらしいので、そこで黒塗りの四角を動かして回答を見つけた人もいました。見た目で隠せてもデータが残ってることがある事とファイル構造や拡張子の

ないファイルを疑ってかかることはこのCTFというものにおいて結構重要であることがわかりました。以下のコマンドは覚えておいた方がいいかもしれません。



file unknownfile      # ファイル形式を推測

xxd unknownfile | head  # 先頭のマジックナンバーを確認

strings unknownfile | less  # 可読文字列を抽出

binwalk unknownfile   # 埋め込みデータを探索







#### Q20.\[Crypto]Block Cipher

100pt



与えられたC言語のソースコードを読み解いて復号してフラグを手にれましょう。



暗号文：cpaw{ruoYced\_ehpigniriks\_i\_llrg\_stae}



crypto100.c



C言語に関しては知識が皆無で何が書いてあるのかは、全くわからなかったのでAIでPythonに直してもらいました。

def decrypt(ciphertext, key):

&nbsp;   # key文字ごとに分割

&nbsp;   blocks = \[ciphertext\[i:i+key] for i in range(0, len(ciphertext), key)]

&nbsp;   # 各ブロックを逆順に

&nbsp;   reversed\_blocks = \[block\[::-1] for block in blocks]

&nbsp;   # 連結して返す

&nbsp;   return ''.join(reversed\_blocks)



ciphertext = "ruoYced\_ehpigniriks\_i\_llrg\_stae"

key = 5



plaintext = decrypt(ciphertext, key)

flag = f"cpaw{{{plaintext}}}"

print(flag)

key=5で違和感のない文字になり答えはcpaw{Your\_deciphering\_skill\_is\_great}となりました。しかし恐らく正規の解法ではないと思うので他パターンも調べてみました。どうやらLinuxでやってる人が多いみたいで以下のコードでできるみたいです。



gcc crypto100.c -o crypto100



./crypto100 ruoYced\_ehpigniriks\_i\_llrg\_stae 4



この場合はkey=4になっていて実行すると答えが出ました。相も変わらず新しいことだらけで、何が何だかわからなかったのですが、とりあえずC言語の実行環境が必要ってことがわかりました。ですが他言語への変換も解法としてはありだと思うのでもし悩んだときは活用しようかと思います。でも以外にも今回は他の人がやってたように結果的には引数を変化させるだけで答えがわかる問題であってコマンドがわかればすぐ溶けたかと思います、なのでコマンドはどんどん覚えていこうと思います。



もう気づけば深夜３時なので、また続きは今度にしようと思います。


#### Q21.\[Reversing]reversing easy!

100pt



フラグを出す実行ファイルがあるのだが、プログラム(elfファイル)作成者が出力する関数を書き忘れてしまったらしい…

reverse100



今回も調べながらですがやっていこうと思います。まずはfileコマンドで調べてみます。



file rev100.elf

rev100.elf: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID\[sha1]=f94360edd84a940de2b74007d4289705601d618d, not stripped



これ見た感じもしかしてsha1の後の文字列解析したら答えかと思ってましたがどうやら違ったみたいでリバースできませんでした。次にstrings rev100.elf | lessで見てみました。



/lib/ld-linux.so.2

libc.so.6

\_IO\_stdin\_used

\_\_stack\_chk\_fail

putchar

printf

\_\_libc\_start\_main

\_\_gmon\_start\_\_

GLIBC\_2.4

GLIBC\_2.0

PTRh

D$L1

D$Fcpawf

D$J{

D$ y

D$$a

D$(k

D$,i

D$0n

D$4i

D$8k

D$<u

D$@!

T$Le3

\[^\_]

;\*2$"

GCC: (Ubuntu 4.8.4-2ubuntu1~14.04) 4.8.4

GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2

.symtab

以上の情報が出ました。cpawのあとの文字をつなげて読めそうだったので読んでみたらcpawf{yakiniku!までなんとなくつなげて読めたので答えはcpaw{yakiniku!}としました。少し応用がきいてきたのかなと思います。思考力が少しだけ育ったような実感があります。







#### Q22.\[Web]Baby's SQLi - Stage 1-

100pt



困ったな……どうしよう……．

ぱろっく先生がキャッシュカードをなくしてしまったショックからデータベースに逃げ込んでしまったんだ．

うーん，君SQL書くのうまそうだね．ちょっと僕もWeb問作らなきゃいけないから，連れ戻すのを任せてもいいかな？

多分，ぱろっく先生はそこまで深いところまで逃げ込んで居ないと思うんだけども……．



とりあえず，逃げ込んだ先は以下のURLだよ．

一応，報酬としてフラグを用意してるからよろしくね！



https://ctf.spica.bz/baby\_sql/



Caution

・sandbox.spica.bzの80,443番ポート以外への攻撃は絶対にしないようにお願いします．

・あなたが利用しているネットワークへの配慮のためhttpsでの通信を推奨します．



大学でSQLは少しだけやったことあるので拙いSQL知識でSELECT \* FROM palloc\_home;と打ってみたら答えが出ました。といっても今回はテーブルの中身すべてを参照するコマンドだったので、効率的とは言えないと思います。なのでURL先のページの問題文であるStage1.Writing SQL

さて，SQLのおさらいです．下のフォームはSQL文を入れるとそのまま動作します．どうやらぱろっく先生は「palloc\_home」というテーブルの2番目にいるようです．に従ってSELECT \* FROM palloc\_home WHERE id = 2;という風にidを指定するのが最適解だと後々調べてわかりました。SQLの勉強も必要だという事が学べました。





#### Q28.\[Network] Can you login？

100pt



古くから存在するネットワークプロトコルを使った通信では、セキュリティを意識していなかったこともあり、様々な情報が暗号化されていないことが多い。そのため、パケットキャプチャをすることでその情報が簡単に見られてしまう可能性がある。

次のパケットを読んで、FLAGを探せ！

network100.pcap

（2021/04/11: 問題ファイルを更新しました。）




とりあえずwiresharkで見てみました。そうすると古い形式であるFTP通信が使われていて、その通信でソートしてみるとユーザー名やパスワードがわかりました。"42","29.903573","192.168.91.138","118.27.110.77","FTP","93","Request: PASS 5f4dcc3b5aa765d61d8327deb882cf99"と出ていたのでPASSが5f4dcc3b5aa765d61d8327deb882cf99であることがわかりましたがどうやら5f4dcc3b5aa765d61d8327deb882cf99はMD5ハッシュ値らしいので、MD5 Centerでリバースしたらpasswordという文字列になりました。あとは118.27.110.77というサーバーのアドレスにアクセスしてユーザー名とパスワードを入れるだけです。ftp 118.27.110.77でサーバにアクセスしてユーザー名とパスワードを入力しましたがパスワードがどうやらpasswordじゃないらしく、もとのMD5形式の5f4dcc3b5aa765d61d8327deb882cf99をパスワードに入力したらログインできました。今回の問題では変換しなおした意味はなかったみたいです。あとはls -aですべてのファイルを一覧表示すると



ftp 118.27.110.77

Connected to 118.27.110.77.

220 Welcome to Cpaw CTF FTP service.

Name (118.27.110.77:korox): cpaw\_user

331 Please specify the password.

Password:

230 Login successful.

Remote system type is UNIX.

Using binary mode to transfer files.

ftp> ls -a

229 Entering Extended Passive Mode (|||60023|)

150 Here comes the directory listing.

drwxr-xr-x    2 ftp      ftp            42 Mar 17  2021 .

drwxr-xr-x    2 ftp      ftp            42 Mar 17  2021 ..

-rw-r--r--    1 ftp      ftp            39 Sep 01  2017 .hidden\_flag\_file

-rw-r--r--    1 ftp      ftp            36 Sep 01  2017 dummy

226 Directory send OK.

ftp> get .hidden\_flag\_file

local: .hidden\_flag\_file remote: .hidden\_flag\_file

229 Entering Extended Passive Mode (|||60024|)

150 Opening BINARY mode data connection for .hidden\_flag\_file (39 bytes).

100% |\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*|    39       21.61 KiB/s    00:00 ETA

226 Transfer complete.

39 bytes received in 00:00 (0.14 KiB/s)

ftp> bye

221 Goodbye.

このように.hidden\_flag\_fileがあったのでgetでファイルをダウンロードし、catで中身を見るとフラッグがありました。答えはcpaw{f4p\_sh0u1d\_b3\_us3d\_in\_3ncryp4i0n}です。今回も結構調べながらチャレンジしてみたのですが、わからないことだらけですべてが勉強になります。





#### Q23.\[Reversing]またやらかした！

200pt



またprintf（）をし忘れたプログラムが見つかった。

とある暗号を解くプログラムらしい…

reversing200



今回も調べながら進めていきました。まずは file コマンドで形式を確認し、ELF 32-bit 実行ファイルであることを確認しました。 次に Ghidra を使って解析するため、WSLg の設定やファイルの移動など環境を整えました。



Ghidra で rev200.elf をインポートし、main 関数をデコンパイルしてみると、local\_7c という配列に 14 個の数値が代入されているのが見えました。 その後の処理を読むと、各要素に 0x19 を XOR して別の場所に格納していることが分かりました。 つまり、この配列が暗号化されたフラグであり、XOR 0x19 をかければ復号できるということです。



そこで、配列の値と XOR のキーを Python に書き写して復号処理を実行しました。



data = \[0x7a, 0x69, 0x78, 0x6e, 0x62, 0x6f, 0x7c, 0x6b,

&nbsp;       0x77, 0x78, 0x74, 0x38, 0x38, 0x64]

key = 0x19

flag = ''.join(chr(x ^ key) for x in data)

print(flag)


これを実行すると、cpaw{vernam!!} というフラグが表示されました。今回の問題では、前回の「printf忘れ」問題の応用で、XOR暗号の復号を行う形でした。 Ghidraでの配列確認と処理の読み取り、そしてPythonでの再現という流れを経験でき、リバースエンジニアリングの基礎的な手順を一通り実践できたと思います。 今後も同様の問題に対応できるよう、ツールの使い方と暗号化処理のパターンを覚えておきたいです。





#### Q24.\[Web]Baby's SQLi - Stage 2-

200pt



うーん，ぱろっく先生深くまで逃げ込んでたか．

そこまで難しくは無いと思うんだけども……．



えっ？何の話か分からない？

さてはStage 1をクリアしてないな．

待っているから，先にStage 1をクリアしてからもう一度来てね．



Caution: sandbox.spica.bzの80,443番ポート以外への攻撃は絶対にしないようにお願いします．



Stage2. Palloc in in Wonderland

さて，簡単なデータベースをくぐり抜けるとそこはまるで童話のような国でした．



ふと前を見るとぱろっく先生がふるふる震えているのが見えました．どうやら，彼はひどく怯えているようです． あなたがそっと手を肩にかけると，ぱろっく先生は飛び跳ね，いつの間にか存在していた扉の中に逃げ込んでいきました．



さて，この部屋は鍵がかかっているようです．困りました．あなたは目の前の入力欄に名前とパスワードを入れなくてはなりません．



おそらく，彼がいつも使うユーザ名は "porisuteru" なのでユーザ名は多分それでしょう．



Stage 1 が SQL に関する問題であったことから、本問題も SQL インジェクションの可能性が高いと判断しました。 ログインフォームにおいて、ユーザ名欄に



porisuteru' --



と入力し、パスワード欄は空欄のまま送信しました。 -- は SQL におけるコメントアウト記号であり、この入力によりパスワード条件が無効化され、ユーザ名のみで認証が通る状態となりました。

結果としてログインに成功し、フラグを取得することができました。 今回の問題では、Stage 1 で学んだ SQL の基礎知識を応用し、ログインバイパスの手法を体験することができました。 SQLインジェクションは非常に危険な脆弱性であり、実際のシステムにおいては入力値の適切なエスケープ処理やプリペアドステートメントの利用など、十分な対策が必要であることを改めて理解しました。 今後も CTF を通じて、このような脆弱性の仕組みと防止策について学びを深めていこうと思います。





Q26.\[PPC]Remainder theorem

200pt



x ≡ 32134 (mod 1584891)

x ≡ 193127 (mod 3438478)



x = ?





フラグはcpaw{xの値}です！

これは、調べたらどうやら中国剰余定理（Chinese Remainder Theorem）を用いて解く問題であり、二つの剰余条件を同時に満たす整数xを求める必要がありました。数学的な背景は複雑に見えましたが、実際には「一方の条件を満たす数列を作り、その中からもう一方の条件も満たすものを探す」という手順で解くことができるみたいです。 手計算では桁が大きく現実的ではないため、Python を用いて計算を行いました。

具体的には、条件1を満たす数列を生成し、各値について条件2を確認するコードを作成しました。その結果、x = 35430270439 という値が得られ、フラグは cpaw{35430270439} となりました。今回の問題を通じて、数学的な問題であってもプログラムや計算ツールを活用することで効率的に解を求められることを学びました。





Q29.\[Crypto] Common World

200pt



Cpaw君は,以下の公開鍵を用いて暗号化された暗号文Cを受け取りました．しかしCpaw君は秘密鍵を忘れてしまいました.Cpaw君のために暗号文を解読してあげましょう.



(e, N) = (11, 236934049743116267137999082243372631809789567482083918717832642810097363305512293474568071369055296264199854438630820352634325357252399203160052660683745421710174826323192475870497319105418435646820494864987787286941817224659073497212768480618387152477878449603008187097148599534206055318807657902493850180695091646575878916531742076951110529004783428260456713315007812112632429296257313525506207087475539303737022587194108436132757979273391594299137176227924904126161234005321583720836733205639052615538054399452669637400105028428545751844036229657412844469034970807562336527158965779903175305550570647732255961850364080642984562893392375273054434538280546913977098212083374336482279710348958536764229803743404325258229707314844255917497531735251105389366176228741806064378293682890877558325834873371615135474627913981994123692172918524625407966731238257519603614744577)



暗号文: 80265690974140286785447882525076768851800986505783169077080797677035805215248640465159446426193422263912423067392651719120282968933314718780685629466284745121303594495759721471318134122366715904



これは…？



フラグは以下のシンタックスです.

cpaw{復号した値}



※復号した値はそのままで良いですが，実は意味があります，余力がある人は考えてみてください.



今回はRSA暗号の複合問題ですが、そもそも複合できるなんて知りませんでした。調べてみたら計算式もだいぶ複雑で文系の私には少し荷が重すぎるように感じました。今回は、公開鍵の数字 e が 11 と小さいことに気づきました。そこで、暗号文が「ある数を 11 回かけたもの」かどうかを試してみました。やり方は難しく考えず、計算ツールを使って暗号文の 11 乗根を求めただけです。

計算した結果、ぴったり 11 乗になっていて、元の数は 424311244315114354 と分かりました。問題の形式に合わせて cpaw{424311244315114354} を提出したところ、正解でした。

今回の学びは三つです。 一つ目は、RSA でも条件がそろうと簡単に解けることがあるということです。 二つ目は、難しい数式を全部理解していなくても、道具を正しく使えば前に進めるということです。 三つ目は、まずは簡単な発想から試してみると、意外と早く答えにたどり着けることがあるということです。

今後も、無理に一人で抱え込まず、ツールやスクリプトを活用して、分かるところからコツコツ進めていきたいと思います。





本日はこれくらいにしようと思います。解いてみて段々わかってきたのですがCrypto系の問題は結構苦手意識があるかもしれないので、少しでも克服できるように努めたいと思います。それとどうやらCpawCTFの問題は以上で終わりみたいなので、次はCpawCTF2に挑戦してみようと思います。


