# juniper-syslog-generator

この Python スクリプトは、Juniper SRX 風のシスログテストデータを生成するツールです。  
実務用スクリプトのテストやシミュレーションに使用できます。

## 特徴

- Juniper SRX フォーマットのシスログを生成
- 通常ログと脅威ログの両方に対応
- タイムスタンプや IP アドレスをランダム生成
- 時間単位で CSV 出力し、ZIP 圧縮
- 24 時間分をまとめた日次 ZIP を生成

## 必要環境

- Python 3.9 以上

## インストール方法

1. リポジトリをクローン：
```bash
git clone https://github.com/Sohey-k/juniper-syslog-generator.git
cd juniper-syslog-generator

2. （任意）仮想環境を作成：
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
venv\Scripts\activate      # Windows

3. 依存パッケージをインストール（必要な場合）：
pip install -r requirements.txt

## 使い方

1. スクリプトを実行:
python generate_logs.py -o output_logs -d 2025-04-28 -H srx-fw01 -r 5000 -t 0.1

## 引数

-o, --output : 出力ディレクトリ（デフォルト: output_logs）

-d, --date : ログの日付（YYYY-MM-DD形式、デフォルト: 2025-04-28）

-H, --hostname : ホスト名（デフォルト: srx-fw01）

-r, --rows : 1時間あたりの行数（デフォルト: 5000）

-t, --threat-ratio : 脅威ログの割合 0.0-1.0（デフォルト: 0.1）

## 実行例

スクリプト実行後、output_logs/ ディレクトリに 24 時間分の ZIP ファイルと日次 ZIP が生成されます。
