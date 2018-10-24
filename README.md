# File-Proxy-Re-Encryption

## OverView
ファイルを暗号化・復号するプログラムです．  
楕円曲線暗号の発展系であるペアリングを仕様しています．
実装された理論は[ここ](https://github.com/jpfaw/File-Proxy-Re-Encryption/blob/images/images/解説.pdf)を見てほしい

## 動作内容
![解説画像](https://raw.githubusercontent.com/jpfaw/File-Proxy-Re-Encryption/images/images/機能図.png)
#### Aが暗号化
入力された鍵を用いてAESでファイルを暗号化します．  
入力された鍵はAの秘密鍵を用いて暗号化され保存されます．
#### Aが復号
Aの秘密鍵を用いて復号します．
#### Aが再暗号化
Aの秘密鍵を用いて暗号化された鍵をBの公開鍵で再暗号化します．
再暗号化された鍵はBの秘密鍵でしか復号できません
#### Bが復号
Bの秘密鍵を用いて鍵を復号し，AESを用いてデータを復号します．

## 使用方法
1. "Plain", "Enc", "Dec"フォルダを用意してください．
1. Plainフォルダに暗号化したいデータを置きます．
1. `./pairing`で実行します． 案内に従って入力してください．  

## プログラム詳細
### 仕様動作
Encフォルダには鍵となるデータ"keyA.txt", "keyB.txt", 再暗号化した場合は"keyC.txt"が出力されます．  
秘密鍵や公開鍵を使用した場合，その旨が表示されます．
#### settings.h
基本となる関数などが記述されています．  
中でも`get_str_std_data`には楕円曲線上の点P, Qと乱数の最大値が記載されています．  
つまりこれらは固定値です．
#### pairing.c
メインプログラムです．  

#### stakeholder
AのフォルダにはAが知っている内容，BのフォルダにはBが知っている内容が入っています．  
これらデータにアクセスする場合，プログラム実行中に通知されます．

#### remove.sh
Enc, Decフォルダの中身をすべて削除します．  
Plainフォルダの`.DS_Store`も削除します．

## 使用ライブラリ
 - OpenSSL (OpenSSL 1.0.2k-fips 26 Jan 2017)
 - GMP (The GNU Multiple Precision Arithmetic Library)
 - TEPLA (University of Tsukuba Elliptic Curve and Pairing Library)

### Notice
以上の内容は2018年10月24日現在の内容です．  
READMEを更新せずプログラムだけ更新されている場合があり，その場合プログラムの動作は上記の限りではありません．
