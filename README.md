# File-Proxy-Re-Encryption

## OverView
ファイルを暗号化・復号するプログラムです．  
暗号化鍵を再暗号化して特定の第三者に一度だけ共有することが可能です．   
楕円曲線暗号の発展系であるペアリングを使用しています．  
実装された理論は[ここ](https://github.com/jpfaw/File-Proxy-Re-Encryption/blob/images/images/解説.pdf)を見てください．

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

## 使用できるモード
1. 再暗号化できない暗号化を行うモード
1. 再暗号化可能な暗号化を行うモード
1. 再暗号化を行うモード
1. 復号モード(ファイル内の状態や鍵の内容を見て暗号化モードを判別し自動で復号します)

## 使用方法
1. pairing.cをコンパイルします．
1. "Plain", "Enc", "Dec"フォルダを用意してください．
1. Plainフォルダに暗号化したいデータを置きます．
1. `./pairing`で実行します． 案内に従って入力してください．  

## プログラム詳細
### 仕様動作
Encフォルダには鍵となるデータ"C_a.txt", 再暗号化した場合は"C_b.txt"が出力されます．  
秘密鍵や公開鍵などを使用した場合，その旨が表示されます．  
これらは本来なら２つのPCが必要ですが，擬似的に１つのパソコンで動作を再現するためのものです．
#### settings.h
基本となる関数などが記述されています．  

#### pairing.c
メインプログラムです．   
1行目にgccコンパイラを使う際のコマンドが書いてあります．

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

## Notice
以上の内容は2018年11月10日現在の内容です．  
READMEを更新せずプログラムだけ更新されている場合があり，その場合プログラムの動作は上記の限りではありません．  
本来ならブランチを分けるものですが，個人用研究をなぜかGitHubでpublicにしてるだけなので...
