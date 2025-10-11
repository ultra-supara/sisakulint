# rev-design

## 目的

既存のコードベースから技術設計文書を逆生成する。実装されたアーキテクチャ、データフロー、API仕様、データベーススキーマ、TypeScriptインターフェースを分析し、設計書として文書化する。

## 前提条件

- 分析対象のコードベースが存在する
- `docs/reverse/` ディレクトリが存在する（なければ作成）
- 可能であれば事前に `rev-tasks.md` を実行済み

## 実行内容

1. **アーキテクチャの分析**
   - プロジェクト構造からアーキテクチャパターンを特定
   - レイヤー構成の確認（MVC、Clean Architecture等）
   - マイクロサービス構成の有無
   - フロントエンド/バックエンドの分離状況

2. **データフローの抽出**
   - ユーザーインタラクションの流れ
   - API呼び出しの流れ
   - データベースアクセスパターン
   - 状態管理の流れ

3. **API仕様の抽出**
   - エンドポイント一覧の生成
   - リクエスト/レスポンス構造の分析
   - 認証・認可方式の確認
   - エラーレスポンス形式

4. **データベーススキーマの逆生成**
   - テーブル定義の抽出
   - リレーションシップの分析
   - インデックス設定の確認
   - 制約条件の抽出

5. **TypeScript型定義の整理**
   - エンティティ型の抽出
   - API型の抽出
   - 共通型の整理
   - 型の依存関係分析

6. **コンポーネント設計の分析**
   - UIコンポーネント階層
   - Propsインターフェース
   - 状態管理の設計
   - ルーティング設計

7. **ファイルの作成**
   - `docs/reverse/{プロジェクト名}-architecture.md` - アーキテクチャ概要
   - `docs/reverse/{プロジェクト名}-dataflow.md` - データフロー図
   - `docs/reverse/{プロジェクト名}-api-specs.md` - API仕様
   - `docs/reverse/{プロジェクト名}-database.md` - DB設計
   - `docs/reverse/{プロジェクト名}-interfaces.ts` - 型定義集約

## 出力フォーマット例

### architecture.md

```markdown
# {プロジェクト名} アーキテクチャ設計（逆生成）

## 分析日時
{実行日時}

## システム概要

### 実装されたアーキテクチャ
- **パターン**: {特定されたアーキテクチャパターン}
- **フレームワーク**: {使用フレームワーク}
- **構成**: {発見された構成}

### 技術スタック

#### フロントエンド
- **フレームワーク**: {React/Vue/Angular等}
- **状態管理**: {Redux/Zustand/Pinia等}
- **UI ライブラリ**: {Material-UI/Ant Design等}
- **スタイリング**: {CSS Modules/styled-components等}

#### バックエンド
- **フレームワーク**: {Express/NestJS/FastAPI等}
- **認証方式**: {JWT/Session/OAuth等}
- **ORM/データアクセス**: {TypeORM/Prisma/Sequelize等}
- **バリデーション**: {Joi/Yup/zod等}

#### データベース
- **DBMS**: {PostgreSQL/MySQL/MongoDB等}
- **キャッシュ**: {Redis/Memcached等 or なし}
- **接続プール**: {実装されているか}

#### インフラ・ツール
- **ビルドツール**: {Webpack/Vite/Rollup等}
- **テストフレームワーク**: {Jest/Vitest/Pytest等}
- **コード品質**: {ESLint/Prettier/SonarQube等}

## レイヤー構成

### 発見されたレイヤー
```
{実際のディレクトリ構造}
```

### レイヤー責務分析
- **プレゼンテーション層**: {実装状況}
- **アプリケーション層**: {実装状況}
- **ドメイン層**: {実装状況}
- **インフラストラクチャ層**: {実装状況}

## デザインパターン

### 発見されたパターン
- **Dependency Injection**: {実装されているか}
- **Repository Pattern**: {実装されているか}
- **Factory Pattern**: {使用箇所}
- **Observer Pattern**: {使用箇所}
- **Strategy Pattern**: {使用箇所}

## 非機能要件の実装状況

### セキュリティ
- **認証**: {実装方式}
- **認可**: {実装方式}
- **CORS設定**: {設定状況}
- **HTTPS対応**: {対応状況}

### パフォーマンス
- **キャッシュ**: {実装状況}
- **データベース最適化**: {インデックス等}
- **CDN**: {使用状況}
- **画像最適化**: {実装状況}

### 運用・監視
- **ログ出力**: {実装状況}
- **エラートラッキング**: {実装状況}
- **メトリクス収集**: {実装状況}
- **ヘルスチェック**: {実装状況}
```

### dataflow.md

```markdown
# データフロー図（逆生成）

## ユーザーインタラクションフロー

### 認証フロー
\`\`\`mermaid
sequenceDiagram
    participant U as ユーザー
    participant F as フロントエンド
    participant B as バックエンド
    participant D as データベース
    
    U->>F: ログイン情報入力
    F->>B: POST /auth/login
    B->>D: ユーザー検証
    D-->>B: ユーザー情報
    B-->>F: JWTトークン
    F-->>U: ログイン完了
\`\`\`

### データ取得フロー
\`\`\`mermaid
flowchart TD
    A[ユーザーアクション] --> B[Reactコンポーネント]
    B --> C[useQueryフック]
    C --> D[Axios HTTP Client]
    D --> E[API Gateway/Express]
    E --> F[コントローラー]
    F --> G[サービス層]
    G --> H[リポジトリ層]
    H --> I[データベース]
    I --> H
    H --> G
    G --> F
    F --> E
    E --> D
    D --> C
    C --> B
    B --> J[UI更新]
\`\`\`

## 状態管理フロー

### {使用されている状態管理ライブラリ} フロー
\`\`\`mermaid
flowchart LR
    A[コンポーネント] --> B[Action Dispatch]
    B --> C[Reducer/Store]
    C --> D[State更新]
    D --> A
\`\`\`

## エラーハンドリングフロー

\`\`\`mermaid
flowchart TD
    A[エラー発生] --> B{エラー種別}
    B -->|認証エラー| C[リダイレクト to ログイン]
    B -->|ネットワークエラー| D[リトライ機能]
    B -->|バリデーションエラー| E[フォームエラー表示]
    B -->|サーバーエラー| F[エラートースト表示]
\`\`\`
```

### api-specs.md

```markdown
# API仕様書（逆生成）

## ベースURL
\`{発見されたベースURL}\`

## 認証方式
{発見された認証方式の詳細}

## エンドポイント一覧

### 認証関連

#### POST /auth/login
**説明**: ユーザーログイン

**リクエスト**:
\`\`\`typescript
{
  email: string;
  password: string;
}
\`\`\`

**レスポンス**:
\`\`\`typescript
{
  success: boolean;
  data: {
    token: string;
    user: {
      id: string;
      email: string;
      name: string;
    }
  };
}
\`\`\`

**エラーレスポンス**:
\`\`\`typescript
{
  success: false;
  error: {
    code: string;
    message: string;
  }
}
\`\`\`

#### POST /auth/logout
**説明**: ユーザーログアウト

**ヘッダー**:
\`\`\`
Authorization: Bearer {token}
\`\`\`

### {その他のエンドポイント}

## エラーコード一覧

| コード | メッセージ | 説明 |
|--------|------------|------|
| AUTH_001 | Invalid credentials | 認証情報が無効 |
| AUTH_002 | Token expired | トークンが期限切れ |
| VALID_001 | Validation failed | バリデーションエラー |

## レスポンス共通形式

### 成功レスポンス
\`\`\`typescript
{
  success: true;
  data: T; // 型は endpoint によって変動
}
\`\`\`

### エラーレスポンス
\`\`\`typescript
{
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  }
}
\`\`\`
```

### database.md

```markdown
# データベース設計（逆生成）

## スキーマ概要

### テーブル一覧
{発見されたテーブル一覧}

### ER図
\`\`\`mermaid
erDiagram
    USERS {
        uuid id PK
        varchar email UK
        varchar name
        timestamp created_at
        timestamp updated_at
    }
    
    POSTS {
        uuid id PK
        uuid user_id FK
        varchar title
        text content
        timestamp created_at
        timestamp updated_at
    }
    
    USERS ||--o{ POSTS : creates
\`\`\`

## テーブル詳細

### users テーブル
\`\`\`sql
{実際のCREATE TABLE文}
\`\`\`

**カラム説明**:
- \`id\`: {説明}
- \`email\`: {説明}
- \`name\`: {説明}

**インデックス**:
- \`idx_users_email\`: email カラムの検索用

### {その他のテーブル}

## 制約・関係性

### 外部キー制約
{発見された外部キー制約}

### ユニーク制約
{発見されたユニーク制約}

## データアクセスパターン

### よく使用されるクエリ
{コードから発見されたクエリパターン}

### パフォーマンス考慮事項
{発見されたインデックス戦略}
```

### interfaces.ts

```typescript
// ======================
// エンティティ型定義
// ======================

export interface User {
  id: string;
  email: string;
  name: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Post {
  id: string;
  userId: string;
  title: string;
  content: string;
  createdAt: Date;
  updatedAt: Date;
  user?: User;
}

// ======================
// API型定義
// ======================

export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  data: {
    token: string;
    user: User;
  };
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
}

// ======================
// コンポーネントProps型
// ======================

export interface LoginFormProps {
  onSubmit: (data: LoginRequest) => void;
  loading?: boolean;
  error?: string;
}

// ======================
// 状態管理型
// ======================

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  loading: boolean;
}

// ======================
// 設定型
// ======================

export interface AppConfig {
  apiBaseUrl: string;
  tokenStorageKey: string;
  supportedLanguages: string[];
}
```

## 分析アルゴリズム

### 1. ファイル走査・パターンマッチング
- AST解析による関数・クラス・インターフェース抽出
- 正規表現による設定ファイル解析
- ディレクトリ構造からのアーキテクチャ推定

### 2. API仕様の自動生成
- Express/NestJS ルート定義の解析
- FastAPI スキーマ定義の解析
- TypeScript型定義からのリクエスト/レスポンス推定

### 3. データベーススキーマの抽出
- マイグレーションファイルの解析
- ORM モデル定義の解析
- SQL ファイルの解析

## 実行コマンド例

```bash
# フル分析（全設計書生成）
claude code rev-design

# 特定の設計書のみ生成
claude code rev-design --target architecture
claude code rev-design --target api
claude code rev-design --target database

# 特定のディレクトリを分析
claude code rev-design --path ./backend

# 出力形式指定
claude code rev-design --format markdown,openapi
```

## 実行後の確認

- 生成された設計書ファイルの一覧を表示
- 抽出されたAPI数、テーブル数、型定義数等の統計情報を表示
- 不足している設計要素や推奨改善点を提示
- 次のリバースエンジニアリングステップ（要件定義生成等）を提案 