# WebAuthn-study

[自社ブログ記事](https://www.ipride.co.jp/blog/11910)について、解説用のサンプルコードです。

## ディレクトリ構造

- `full-scratch`ディレクトリ
  - 外部ライブラリを使わず、WebAuthnの登録/認証処理を行うクライアント/サーバーを実装
- `with-library`ディレクトリ
  - 外部ライブラリを使って、WebAuthnの登録/認証処理を行うクライアント/サーバーを実装

## 環境構築方法

`full-scratch`ディレクトリにおいても、`with-library`ディレクトリにおいても、以下の手順で環境構築を行ってください。

1. クライアント (`sample-webauthn-app`) の環境構築
   - `sample-webauthn-app`ディレクトリに移動
   - `npm install`を実行
2. サーバー (`sample-webauthn-server`) の環境構築
   - `sample-webauthn-server`ディレクトリに移動
   - `pip install -r requirements.txt`を実行

## 実行方法

1. クライアント (`sample-webauthn-app`) の起動
  - `sample-webauthn-app`ディレクトリに移動
  - `npm run dev`を実行
2. サーバー (`sample-webauthn-server`) の起動
  - `sample-webauthn-server`ディレクトリに移動
  - `python main.py`を実行
3. ブラウザで`http://localhost:3000`にアクセス
4. Name と DisplayName を入力し、Register ボタンをクリック
5. 正常に完了したら、「`Success to register.`」というステータスメッセージが表示される
6. 5.を確認した後に、Login ボタンをクリック
7. 正常に完了したら、「`Success to login.`」というステータスメッセージが表示される
