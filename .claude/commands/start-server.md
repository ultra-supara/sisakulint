# 開発サーバ起動・管理

開発環境のサーバを起動・管理するコマンドです。

## サーバ起動確認・管理

開発開始前にサーバの状態を確認し、必要に応じて起動します：

```bash
# 既存のViteサーバ確認
ps aux | grep -E "vite.*--port 3000" | grep -v grep

# サーバが起動していない場合は新規起動
if ! ps aux | grep -E "vite.*--port 3000" | grep -v grep > /dev/null; then
  echo "サーバが起動していません。開発サーバを起動します..."
  npm run dev &
  echo "サーバ起動中... 5秒待機します"
  sleep 5
else
  echo "既存のサーバが見つかりました。そのまま利用します。"
  ps aux | grep -E "vite.*--port 3000" | grep -v grep | awk '{print "PID: " $2 " - Viteサーバが既に起動中"}'
fi

# サーバ動作確認
echo "サーバ動作確認中..."
curl -s http://localhost:3000 > /dev/null && echo "✅ サーバは正常に動作しています" || echo "⚠️ サーバに接続できません"
```

## サーバ管理コマンド

### サーバ状態確認

```bash
# 現在動作中のサーバプロセス確認
ps aux | grep -E "vite.*--port 3000" | grep -v grep

# ポート使用状況確認
lsof -i :3000
```

### サーバ停止

```bash
# Viteサーバの停止
pkill -f "vite.*--port 3000"

# 強制停止（上記で停止しない場合）
ps aux | grep -E "vite.*--port 3000" | grep -v grep | awk '{print $2}' | xargs kill -9
```

### サーバ再起動

```bash
# サーバ停止
pkill -f "vite.*--port 3000"

# 少し待機
sleep 2

# サーバ再起動
npm run dev &

# 起動確認
sleep 5
curl -s http://localhost:3000 > /dev/null && echo "✅ サーバは正常に動作しています" || echo "⚠️ サーバに接続できません"
```

## 使用場面

- TDD開発開始前の環境準備
- サーバが停止している場合の復旧
- サーバの状態確認が必要な場合
- 開発環境のセットアップ時

## 注意事項

- ポート3000が他のプロセスに使用されている場合は、該当プロセスを終了してください
- サーバ起動後は、ブラウザで http://localhost:3000 にアクセスして動作確認できます
- バックグラウンドで起動したサーバは、作業終了時に適切に停止することを推奨します