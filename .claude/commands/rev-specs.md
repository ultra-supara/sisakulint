# rev-specs

## 目的

既存のコードベースから包括的なテストケースと仕様書を逆生成する。実装されたビジネスロジック、API動作、UI コンポーネントの動作を分析し、不足しているテストケースを特定・生成し、仕様書として文書化する。

## 前提条件

- 分析対象のコードベースが存在する
- `docs/reverse/` ディレクトリが存在する（なければ作成）
- 可能であれば事前に `rev-requirements.md`, `rev-design.md` を実行済み

## 実行内容

1. **既存テストの分析**
   - 単体テスト（Unit Test）の実装状況確認
   - 統合テスト（Integration Test）の実装状況確認
   - E2Eテスト（End-to-End Test）の実装状況確認
   - テストカバレッジの測定

2. **実装コードからテストケースの逆生成**
   - 関数・メソッドの引数・戻り値からのテストケース生成
   - 条件分岐からの境界値テスト生成
   - エラーハンドリングからの異常系テスト生成
   - データベース操作からのデータテスト生成

3. **API仕様からテストケースの生成**
   - 各エンドポイントの正常系テスト
   - 認証・認可テスト
   - バリデーションエラーテスト
   - HTTPステータスコードテスト

4. **UI コンポーネントからテストケースの生成**
   - コンポーネントレンダリングテスト
   - ユーザーインタラクションテスト
   - 状態変更テスト
   - プロパティ変更テスト

5. **パフォーマンス・セキュリティテストケースの生成**
   - 負荷テストシナリオ
   - セキュリティ脆弱性テスト
   - レスポンス時間テスト

6. **テスト仕様書の生成**
   - テスト計画書
   - テストケース一覧
   - テスト環境仕様
   - テスト手順書

7. **ファイルの作成**
   - `docs/reverse/{プロジェクト名}-test-specs.md` - テスト仕様書
   - `docs/reverse/{プロジェクト名}-test-cases.md` - テストケース一覧
   - `docs/reverse/tests/` - 生成されたテストコード

## 出力フォーマット例

### test-specs.md

```markdown
# {プロジェクト名} テスト仕様書（逆生成）

## 分析概要

**分析日時**: {実行日時}
**対象コードベース**: {パス}
**テストカバレッジ**: {現在のカバレッジ}%
**生成テストケース数**: {生成数}個
**実装推奨テスト数**: {推奨数}個

## 現在のテスト実装状況

### テストフレームワーク
- **単体テスト**: {Jest/Vitest/pytest等}
- **統合テスト**: {Supertest/TestContainers等}
- **E2Eテスト**: {Cypress/Playwright等}
- **コードカバレッジ**: {istanbul/c8等}

### テストカバレッジ詳細

| ファイル/ディレクトリ | 行カバレッジ | 分岐カバレッジ | 関数カバレッジ |
|---------------------|-------------|-------------|-------------|
| src/auth/ | 85% | 75% | 90% |
| src/users/ | 60% | 45% | 70% |
| src/components/ | 40% | 30% | 50% |
| **全体** | **65%** | **55%** | **75%** |

### テストカテゴリ別実装状況

#### 単体テスト
- [x] **認証サービス**: auth.service.spec.ts
- [x] **ユーザーサービス**: user.service.spec.ts
- [ ] **データ変換ユーティリティ**: 未実装
- [ ] **バリデーションヘルパー**: 未実装

#### 統合テスト
- [x] **認証API**: auth.controller.spec.ts
- [ ] **ユーザー管理API**: 未実装
- [ ] **データベース操作**: 未実装

#### E2Eテスト
- [ ] **ユーザーログインフロー**: 未実装
- [ ] **データ操作フロー**: 未実装
- [ ] **エラーハンドリング**: 未実装

## 生成されたテストケース

### API テストケース

#### POST /auth/login - ログイン認証

**正常系テスト**
```typescript
describe('POST /auth/login', () => {
  it('有効な認証情報でログイン成功', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'password123'
      });
    
    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.data.token).toBeDefined();
    expect(response.body.data.user.email).toBe('test@example.com');
  });

  it('JWTトークンが正しい形式で返される', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send(validCredentials);
    
    const token = response.body.data.token;
    expect(token).toMatch(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/);
  });
});
```

**異常系テスト**
```typescript
describe('POST /auth/login - 異常系', () => {
  it('無効なメールアドレスでエラー', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'invalid-email',
        password: 'password123'
      });
    
    expect(response.status).toBe(400);
    expect(response.body.success).toBe(false);
    expect(response.body.error.code).toBe('VALIDATION_ERROR');
  });

  it('存在しないユーザーでエラー', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'nonexistent@example.com',
        password: 'password123'
      });
    
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('パスワード間違いでエラー', async () => {
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: 'wrongpassword'
      });
    
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('INVALID_CREDENTIALS');
  });
});
```

**境界値テスト**
```typescript
describe('POST /auth/login - 境界値', () => {
  it('最小文字数パスワードでテスト', async () => {
    // 8文字（最小要件）
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: 'test@example.com',
        password: '12345678'
      });
    
    expect(response.status).toBe(200);
  });

  it('最大文字数メールアドレスでテスト', async () => {
    // 255文字（最大要件）
    const longEmail = 'a'.repeat(243) + '@example.com';
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: longEmail,
        password: 'password123'
      });
    
    expect(response.status).toBe(400);
  });
});
```

### UIコンポーネントテストケース

#### LoginForm コンポーネント

**レンダリングテスト**
```typescript
import { render, screen } from '@testing-library/react';
import { LoginForm } from './LoginForm';

describe('LoginForm', () => {
  it('必要な要素が表示される', () => {
    render(<LoginForm onSubmit={jest.fn()} />);
    
    expect(screen.getByLabelText('メールアドレス')).toBeInTheDocument();
    expect(screen.getByLabelText('パスワード')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'ログイン' })).toBeInTheDocument();
  });

  it('初期状態でエラーメッセージが非表示', () => {
    render(<LoginForm onSubmit={jest.fn()} />);
    
    expect(screen.queryByText(/エラー/)).not.toBeInTheDocument();
  });
});
```

**ユーザーインタラクションテスト**
```typescript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

describe('LoginForm - ユーザーインタラクション', () => {
  it('フォーム送信時にonSubmitが呼ばれる', async () => {
    const mockSubmit = jest.fn();
    render(<LoginForm onSubmit={mockSubmit} />);
    
    await userEvent.type(screen.getByLabelText('メールアドレス'), 'test@example.com');
    await userEvent.type(screen.getByLabelText('パスワード'), 'password123');
    await userEvent.click(screen.getByRole('button', { name: 'ログイン' }));
    
    expect(mockSubmit).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123'
    });
  });

  it('バリデーションエラー時に送信されない', async () => {
    const mockSubmit = jest.fn();
    render(<LoginForm onSubmit={mockSubmit} />);
    
    await userEvent.click(screen.getByRole('button', { name: 'ログイン' }));
    
    expect(mockSubmit).not.toHaveBeenCalled();
    expect(screen.getByText('メールアドレスは必須です')).toBeInTheDocument();
  });
});
```

### サービス層テストケース

#### AuthService 単体テスト

```typescript
import { AuthService } from './auth.service';
import { UserRepository } from './user.repository';

jest.mock('./user.repository');

describe('AuthService', () => {
  let authService: AuthService;
  let mockUserRepository: jest.Mocked<UserRepository>;

  beforeEach(() => {
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    authService = new AuthService(mockUserRepository);
  });

  describe('login', () => {
    it('有効な認証情報でユーザー情報とトークンを返す', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        hashedPassword: 'hashed_password'
      };
      
      mockUserRepository.findByEmail.mockResolvedValue(mockUser);
      jest.spyOn(authService, 'verifyPassword').mockResolvedValue(true);
      jest.spyOn(authService, 'generateToken').mockReturnValue('mock_token');

      const result = await authService.login('test@example.com', 'password');

      expect(result).toEqual({
        user: { id: '1', email: 'test@example.com' },
        token: 'mock_token'
      });
    });

    it('存在しないユーザーでエラーをスロー', async () => {
      mockUserRepository.findByEmail.mockResolvedValue(null);

      await expect(
        authService.login('nonexistent@example.com', 'password')
      ).rejects.toThrow('Invalid credentials');
    });
  });
});
```

## パフォーマンステストケース

### 負荷テスト

```typescript
describe('パフォーマンステスト', () => {
  it('ログインAPI - 100同時接続テスト', async () => {
    const promises = Array.from({ length: 100 }, () =>
      request(app).post('/auth/login').send(validCredentials)
    );

    const startTime = Date.now();
    const responses = await Promise.all(promises);
    const endTime = Date.now();

    // 全てのリクエストが成功
    responses.forEach(response => {
      expect(response.status).toBe(200);
    });

    // 応答時間が5秒以内
    expect(endTime - startTime).toBeLessThan(5000);
  });

  it('データベース - 大量データ検索性能', async () => {
    // 1000件のテストデータを作成
    await createTestData(1000);

    const startTime = Date.now();
    const response = await request(app)
      .get('/users')
      .query({ limit: 100, offset: 0 });
    const endTime = Date.now();

    expect(response.status).toBe(200);
    expect(endTime - startTime).toBeLessThan(1000); // 1秒以内
  });
});
```

### セキュリティテスト

```typescript
describe('セキュリティテスト', () => {
  it('SQLインジェクション対策', async () => {
    const maliciousInput = "'; DROP TABLE users; --";
    
    const response = await request(app)
      .post('/auth/login')
      .send({
        email: maliciousInput,
        password: 'password'
      });

    // システムが正常に動作し、データベースが破損していない
    expect(response.status).toBe(400);
    
    // ユーザーテーブルが依然として存在することを確認
    const usersResponse = await request(app)
      .get('/users')
      .set('Authorization', 'Bearer ' + validToken);
    expect(usersResponse.status).not.toBe(500);
  });

  it('XSS対策', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    
    const response = await request(app)
      .post('/users')
      .set('Authorization', 'Bearer ' + validToken)
      .send({
        name: xssPayload,
        email: 'test@example.com'
      });

    // レスポンスでスクリプトがエスケープされている
    expect(response.body.data.name).not.toContain('<script>');
    expect(response.body.data.name).toContain('&lt;script&gt;');
  });
});
```

## E2Eテストケース

### Playwright/Cypress テストシナリオ

```typescript
// ユーザーログインフロー E2Eテスト
describe('ユーザーログインフロー', () => {
  it('正常なログインからダッシュボード表示まで', async () => {
    await page.goto('/login');
    
    // ログインフォーム入力
    await page.fill('[data-testid="email-input"]', 'test@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    
    // ダッシュボードへリダイレクト
    await page.waitForURL('/dashboard');
    
    // ユーザー情報表示確認
    await expect(page.locator('[data-testid="user-name"]')).toContainText('テストユーザー');
    
    // ログアウト機能確認
    await page.click('[data-testid="logout-button"]');
    await page.waitForURL('/login');
  });

  it('ログイン失敗時のエラー表示', async () => {
    await page.goto('/login');
    
    await page.fill('[data-testid="email-input"]', 'wrong@example.com');
    await page.fill('[data-testid="password-input"]', 'wrongpassword');
    await page.click('[data-testid="login-button"]');
    
    // エラーメッセージ表示確認
    await expect(page.locator('[data-testid="error-message"]'))
      .toContainText('認証情報が正しくありません');
  });
});
```

## テスト環境設定

### データベーステスト設定

```typescript
// テスト用データベース設定
beforeAll(async () => {
  // テスト用データベース接続
  await setupTestDatabase();
  
  // マイグレーション実行
  await runMigrations();
});

beforeEach(async () => {
  // 各テスト前にデータをクリーンアップ
  await cleanupDatabase();
  
  // 基本テストデータ投入
  await seedTestData();
});

afterAll(async () => {
  // テスト用データベース切断
  await teardownTestDatabase();
});
```

### モック設定

```typescript
// 外部サービスのモック
jest.mock('./email.service', () => ({
  EmailService: jest.fn().mockImplementation(() => ({
    sendEmail: jest.fn().mockResolvedValue(true)
  }))
}));

// 環境変数のモック
process.env.JWT_SECRET = 'test-secret';
process.env.NODE_ENV = 'test';
```

## 不足テストの優先順位

### 高優先度（即座に実装推奨）
1. **E2Eテストスイート** - ユーザーフロー全体の動作保証
2. **API統合テスト** - バックエンドAPI全体のテスト
3. **セキュリティテスト** - 脆弱性対策の検証

### 中優先度（次のスプリントで実装）
1. **パフォーマンステスト** - 負荷・応答時間テスト
2. **UIコンポーネントテスト** - フロントエンド動作保証
3. **データベーステスト** - データ整合性テスト

### 低優先度（継続的改善として実装）
1. **ブラウザ互換性テスト** - 複数ブラウザでの動作確認
2. **アクセシビリティテスト** - a11y対応確認
3. **国際化テスト** - 多言語対応確認

```

### test-cases.md

```markdown
# {プロジェクト名} テストケース一覧（逆生成）

## テストケース概要

| ID | テスト名 | カテゴリ | 優先度 | 実装状況 | 推定工数 |
|----|----------|----------|--------|----------|----------|
| TC-001 | ログイン正常系 | API | 高 | ✅ | 2h |
| TC-002 | ログイン異常系 | API | 高 | ✅ | 3h |
| TC-003 | E2Eログインフロー | E2E | 高 | ❌ | 4h |
| TC-004 | パフォーマンス負荷テスト | パフォーマンス | 中 | ❌ | 6h |

## 詳細テストケース

### TC-001: ログインAPI正常系テスト

**テスト目的**: 有効な認証情報でのログイン機能を検証

**事前条件**:
- テストユーザーがデータベースに存在する
- パスワードが正しくハッシュ化されている

**テスト手順**:
1. POST /auth/login にリクエスト送信
2. 有効なemail, passwordを含むJSONを送信
3. レスポンスを確認

**期待結果**:
- HTTPステータス: 200
- success: true
- data.token: JWT形式のトークン
- data.user: ユーザー情報

**実装ファイル**: `auth.controller.spec.ts`

### TC-002: ログインAPI異常系テスト

**テスト目的**: 無効な認証情報での適切なエラーハンドリングを検証

**テストケース**:
1. 存在しないメールアドレス
2. 無効なパスワード
3. 不正なメール形式
4. 空文字・null値
5. SQLインジェクション攻撃

**期待結果**:
- 適切なHTTPステータスコード
- 統一されたエラーレスポンス形式
- セキュリティ脆弱性がない

**実装状況**: ✅ 部分的実装

```

## テストコード生成アルゴリズム

### 1. 静的解析によるテストケース抽出

```
1. 関数シグネチャ解析 → 引数・戻り値のテストケース
2. 条件分岐解析 → 分岐網羅テストケース
3. 例外処理解析 → 異常系テストケース
4. データベースアクセス解析 → データテストケース
```

### 2. 動的解析によるテスト生成

```
1. API呼び出しログ → 実際の使用パターンテスト
2. ユーザー操作ログ → E2Eテストシナリオ
3. パフォーマンスログ → 負荷テストシナリオ
```

### 3. テストカバレッジギャップ分析

```
1. 現在のカバレッジ測定
2. 未テスト行・分岐の特定
3. クリティカルパスの特定
4. リスクベース優先順位付け
```

## 実行コマンド例

```bash
# フル分析（全テストケース生成）
claude code rev-specs

# 特定のテストカテゴリのみ生成
claude code rev-specs --type unit
claude code rev-specs --type integration
claude code rev-specs --type e2e

# 特定のファイル/ディレクトリを対象
claude code rev-specs --path ./src/auth

# テストコードの実際の生成と出力
claude code rev-specs --generate-code

# カバレッジレポートと合わせて分析
claude code rev-specs --with-coverage

# 優先度フィルタリング
claude code rev-specs --priority high
```

## 実行後の確認

- 現在のテストカバレッジと不足部分の詳細レポート表示
- 生成されたテストケース数と推定実装工数を表示
- 優先順位付けされた実装推奨リストを提示
- テスト環境の設定要件と推奨ツールを提案
- CI/CD パイプラインへの統合案を提示 