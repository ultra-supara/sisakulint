# direct-setup

## 目的

DIRECTタスクの設定作業を実行します。設計文書に基づいて環境構築、設定ファイル作成、依存関係のインストールなどを行います。

## 前提条件

- タスクIDが提供されている
- 関連する設計文書が存在する
- 必要な権限と環境が準備されている

## 実行内容

1. **設計文書の確認**
   - `docs/design/{要件名}/architecture.md` を確認
   - `docs/design/{要件名}/database-schema.sql` を確認
   - その他関連する設計文書を確認

2. **設定作業の実行**
   - 環境変数の設定
   - 設定ファイルの作成・更新
   - 依存関係のインストール
   - データベースの初期化
   - サービスの起動設定
   - 権限の設定

3. **作業記録の作成**
   - 実行したコマンドの記録
   - 変更した設定の記録
   - 遭遇した問題と解決方法の記録

## 出力先

作業記録は `docs/implements/{TASK-ID}/` ディレクトリに以下のファイルとして作成されます：
- `setup-report.md`: 設定作業実行記録

## 出力フォーマット例

````markdown
# {TASK-ID} 設定作業実行

## 作業概要

- **タスクID**: {TASK-ID}
- **作業内容**: {設定作業の概要}
- **実行日時**: {実行日時}
- **実行者**: {実行者}

## 設計文書参照

- **参照文書**: {参照した設計文書のリスト}
- **関連要件**: {REQ-XXX, REQ-YYY}

## 実行した作業

### 1. 環境変数の設定

```bash
# 実行したコマンド
export NODE_ENV=development
export DATABASE_URL=postgresql://localhost:5432/mydb
```
````

**設定内容**:

- NODE_ENV: 開発環境に設定
- DATABASE_URL: PostgreSQLデータベースのURL

### 2. 設定ファイルの作成

**作成ファイル**: `config/database.json`

```json
{
  "development": {
    "host": "localhost",
    "port": 5432,
    "database": "mydb"
  }
}
```

### 3. 依存関係のインストール

```bash
# 実行したコマンド
npm install express pg
```

**インストール内容**:

- express: Webフレームワーク
- pg: PostgreSQLクライアント

### 4. データベースの初期化

```bash
# 実行したコマンド
createdb mydb
psql -d mydb -f database-schema.sql
```

**実行内容**:

- データベース作成
- スキーマの適用

## 作業結果

- [ ] 環境変数の設定完了
- [ ] 設定ファイルの作成完了
- [ ] 依存関係のインストール完了
- [ ] データベースの初期化完了
- [ ] サービスの起動設定完了

## 遭遇した問題と解決方法

### 問題1: {問題の概要}

- **発生状況**: {問題が発生した状況}
- **エラーメッセージ**: {エラーメッセージ}
- **解決方法**: {解決方法}

## 次のステップ

- `direct-verify.md` を実行して設定を確認
- 必要に応じて設定の調整を実施

```

## 実行後の確認
- `docs/implements/{TASK-ID}/setup-report.md` ファイルが作成されていることを確認
- 設定が正しく適用されていることを確認
- 次のステップ（direct-verify）の準備が整っていることを確認

## ディレクトリ作成

実行前に必要なディレクトリを作成してください：
```bash
mkdir -p docs/implements/{TASK-ID}
```
```
