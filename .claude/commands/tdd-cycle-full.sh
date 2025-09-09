#!/bin/bash

# TDD フルサイクル実行スクリプト
# Usage: ./tdd-cycle-full.sh <test_case_name>

# 開始時間記録
START_TIME=$(date +%s)

if [ $# -ne 1 ]; then
    echo "Usage: $0 <test_case_name>"
    exit 1
fi

TEST_CASE_NAME=$1

# カラー定義
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Claude コマンド共通設定
ALLOWED_TOOLS="Write,Edit,Bash(npm:*),Bash(node:*)"
DISALLOWED_TOOLS="Bash(git *)"
VERIFY_ALLOWED_TOOLS="Write,Edit,Bash(npm:*),Bash(node:*),Bash(git status),Bash(git diff)"
VERIFY_DISALLOWED_TOOLS="Bash(git add),Bash(git commit),Bash(git push)"

# TDDサイクル実行関数
run_tdd_cycle() {
    local test_case=$1
    
    echo "🔴 RED フェーズ開始..."
    if ! claude -p "/tdd-red $test_case 不足テストの追加実装" --allowedTools "$ALLOWED_TOOLS" --disallowedTools "$DISALLOWED_TOOLS"; then
        echo -e "${RED}❌ RED フェーズ失敗${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ RED フェーズ完了${NC}"
    
    echo "🟢 GREEN フェーズ開始..."
    if ! claude -p "/tdd-green $test_case" --allowedTools "$ALLOWED_TOOLS" --disallowedTools "$DISALLOWED_TOOLS"; then
        echo -e "${RED}❌ GREEN フェーズ失敗${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ GREEN フェーズ完了${NC}"
    
    echo "🔵 REFACTOR フェーズ開始..."
    if ! claude -p "/tdd-refactor $test_case" --allowedTools "$ALLOWED_TOOLS" --disallowedTools "$DISALLOWED_TOOLS"; then
        echo -e "${RED}❌ REFACTOR フェーズ失敗${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ REFACTOR フェーズ完了${NC}"
    
    echo "🔍 VERIFY COMPLETE フェーズ開始..."
    local verify_result
    verify_result=$(claude -p "/tdd-verify-complete $test_case" --allowedTools "$VERIFY_ALLOWED_TOOLS" --disallowedTools "$VERIFY_DISALLOWED_TOOLS" 2>&1)
    local verify_exit_code=$?
    
    if [ $verify_exit_code -ne 0 ]; then
        echo -e "${RED}❌ VERIFY COMPLETE フェーズ失敗${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ VERIFY COMPLETE フェーズ完了${NC}"
    
    # 結果の判定
    if echo "$verify_result" | grep -E "(品質基準を満たしています|実装完了|検証完了)" > /dev/null; then
        echo -e "${GREEN}🎉 TDDサイクル完了${NC}: $test_case のTDDサイクルが正常に完了しました"
        return 0
    elif echo "$verify_result" | grep -E "(未実装|品質基準に満たない|追加実装が必要)" > /dev/null; then
        echo -e "${YELLOW}🔄 TDDサイクル継続${NC}: 品質基準に満たない項目が見つかりました。RED フェーズに戻ります..."
        return 1
    else
        echo -e "${YELLOW}⚠️  判定結果が不明確です${NC}"
        echo "--- VERIFY COMPLETE フェーズの出力 ---"
        echo "$verify_result"
        echo "--- 出力終了 ---"
        echo ""
        echo -e "${BLUE}以下から選択してください:${NC}"
        echo "1) 完了として扱う（TDDサイクルを終了）"
        echo "2) RED フェーズから継続する"
        echo "3) スクリプトを終了する"
        echo ""
        
        while true; do
            read -p "選択 (1/2/3): " choice
            case $choice in
                1)
                    echo -e "${GREEN}🎉 TDDサイクル完了${NC}: ユーザー判断により完了とします"
                    return 0
                    ;;
                2)
                    echo -e "${YELLOW}🔄 TDDサイクル継続${NC}: ユーザー判断により RED フェーズに戻ります"
                    return 1
                    ;;
                3)
                    echo -e "${BLUE}👋 スクリプトを終了します${NC}"
                    exit 0
                    ;;
                *)
                    echo "無効な選択です。1, 2, または 3 を入力してください。"
                    ;;
            esac
        done
    fi
}

# 完了時間表示関数
show_completion_time() {
    local exit_code=$1
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    printf "⏱️  実行時間: "
    if [ $hours -gt 0 ]; then
        printf "%d時間%d分%d秒\n" $hours $minutes $seconds
    elif [ $minutes -gt 0 ]; then
        printf "%d分%d秒\n" $minutes $seconds
    else
        printf "%d秒\n" $seconds
    fi
    
    printf "🕐 終了時刻: %s\n" "$(date +'%Y-%m-%d %H:%M:%S')"
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ 正常終了${NC}"
    else
        echo -e "${RED}❌ エラー終了${NC}"
    fi
}

# trap設定（エラー終了時にも時間表示）
trap 'show_completion_time $?' EXIT

# メインループ
echo "TDD フルサイクル実行開始: $TEST_CASE_NAME"
max_cycles=5
cycle_count=0

while [ $cycle_count -lt $max_cycles ]; do
    cycle_count=$((cycle_count + 1))
    echo -e "${BLUE}=== サイクル $cycle_count 開始 ===${NC}"
    
    if run_tdd_cycle "$TEST_CASE_NAME"; then
        echo -e "${GREEN}🎉 全体完了: TDDサイクルが正常に完了しました${NC}"
        exit 0
    fi
    
    echo -e "${YELLOW}サイクル $cycle_count 完了、次のサイクルに進みます...${NC}"
    echo ""
done

echo -e "${RED}❌ 最大サイクル数($max_cycles)に達しました。手動で確認してください。${NC}"
exit 1