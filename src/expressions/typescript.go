package expressions

import (
	"fmt"
	"sort"
	"strings"
)

// ExprType は式内の値の型のためのインターフェースです。
type ExprType interface {
	// String は型の文字列表現を返します。
	String() string
	// Assignable は他の型がこの型に割り当て可能かどうかを返します。
	Assignable(other ExprType) bool
	// Merge は他の型をこの型にマージします。他の型がこの型と衝突する場合、
	// マージされた結果はフォールバックとして any 型になります。
	Merge(other ExprType) ExprType
	// DeepCopy は自身のディープコピーを作成します。その子型も再帰的にコピーされます。
	DeepCopy() ExprType
}

// UnknownType は任意の型を表します。
// これはまた、その型が静的には知られていないため、型チェックができないことを示します。
type UnknownType struct{}

func (ty UnknownType) String() string {
	return "any"
}

func (ty UnknownType) Assignable(_ ExprType) bool {
	return true
}

func (ty UnknownType) Merge(other ExprType) ExprType {
	return ty
}

func (ty UnknownType) DeepCopy() ExprType {
	return ty
}

// NullType は null 値のための型です。
type NullType struct{}

func (ty NullType) String() string {
	return "null"
}

func (ty NullType) Assignable(other ExprType) bool {
	switch other.(type) {
	case NullType:
		return true
	case UnknownType:
		return true
	default:
		return false
	}
}

func (ty NullType) Merge(other ExprType) ExprType {
	if _, ok := other.(NullType); ok {
		return ty
	}
	return UnknownType{}
}

func (ty NullType) DeepCopy() ExprType {
	return ty
}

// NumberType は数値（整数や浮動小数点数）のための型です。
type NumberType struct{}

func (ty NumberType) String() string {
	return "number"
}

func (ty NumberType) Assignable(other ExprType) bool {
	switch other.(type) {
	case NumberType:
		return true
	case UnknownType:
		return true
	default:
		return false
	}
}

func (ty NumberType) Merge(other ExprType) ExprType {
	switch other.(type) {
	case NumberType:
		return ty
	case StringType:
		return other
	default:
		return UnknownType{}
	}
}

func (ty NumberType) DeepCopy() ExprType {
	return ty
}

// BoolType はブール値（真偽値）のための型です。
type BoolType struct{}

func (ty BoolType) String() string {
	return "bool"
}

func (ty BoolType) Assignable(other ExprType) bool {
	// 任意の型は bool に変換できます。
	// 例:
	//    if: ${{ steps.foo }}
	return true
}

func (ty BoolType) Merge(other ExprType) ExprType {
	switch other.(type) {
	case BoolType:
		return ty
	case StringType:
		return other
	default:
		return UnknownType{}
	}
}

func (ty BoolType) DeepCopy() ExprType {
	return ty
}

// StringType は文字列値のための型です。
type StringType struct{}

func (ty StringType) String() string {
	return "string"
}

func (ty StringType) Assignable(other ExprType) bool {
	// Bool および null 型も文字列に強制変換できますが、
	// ほとんどの場合、これらの強制変換は間違いでしょう。
	switch other.(type) {
	case StringType, NumberType, UnknownType:
		return true
	default:
		return false
	}
}

func (ty StringType) Merge(other ExprType) ExprType {
	switch other.(type) {
	case StringType, NumberType, BoolType:
		return ty
	default:
		return UnknownType{}
	}
}

func (ty StringType) DeepCopy() ExprType {
	return ty
}

// ObjectType はキーと値のペアを持つオブジェクトのための型です。
type ObjectType struct {
	// Props はプロパティ名からその型へのマップです。
	Props map[string]ExprType
	// Mapped はこのオブジェクトの要素型です。これはすべてのプロパティがこの型を持つことを意味します。
	// 例えば、env コンテキストの要素型は string です。
	// AnyType はプロパティの型が任意であることを意味し、緩いオブジェクトを形成します。
	// nil を設定すると、プロパティは型にマップされず、厳密なオブジェクトを形成します。
	// Invariant: Props フィールド内のすべての型は、この型に割り当て可能でなければなりません。
	Mapped ExprType
}

// NewEmptyObjectType は未知のプロパティを許可する新しい緩い ObjectType インスタンスを作成します。
// 未知のプロパティにアクセスすると、その値は any にフォールバックします。
func NewEmptyObjectType() *ObjectType {
	return &ObjectType{map[string]ExprType{}, UnknownType{}}
}

// NewObjectType は与えられたプロパティで未知のプロパティを許可する新しい緩い ObjectType インスタンスを作成します。
func NewObjectType(props map[string]ExprType) *ObjectType {
	return &ObjectType{props, UnknownType{}}
}

// NewEmptyStrictObjectType は未知のプロパティを許可しない新しい ObjectType インスタンスを作成します。
func NewEmptyStrictObjectType() *ObjectType {
	return &ObjectType{map[string]ExprType{}, nil}
}

// NewStrictObjectType は与えられたプロパティタイプで未知のプロパティを許可しない新しい ObjectType インスタンスを作成します。
func NewStrictObjectType(props map[string]ExprType) *ObjectType {
	return &ObjectType{props, nil}
}

// NewMapObjectType は特定の型の値にキーをマップする新しい ObjectType を作成します。
func NewMapObjectType(t ExprType) *ObjectType {
	return &ObjectType{nil, t}
}

// IsStrict は型が厳密なオブジェクトであるかどうかを返します。これは未知のプロパティが許可されていないことを意味します。
func (ty *ObjectType) IsStrict() bool {
	return ty.Mapped == nil
}

// IsLoose は型が緩いオブジェクトであるかどうかを返します。これは任意の未知のプロパティが許可されていることを意味します。
func (ty *ObjectType) IsLoose() bool {
	_, ok := ty.Mapped.(UnknownType)
	return ok
}

// Strict はオブジェクトを厳密な型に設定します。これは既知のプロパティのみが許可されることを意味します。
func (ty *ObjectType) Strict() {
	ty.Mapped = nil
}

// Loose はオブジェクトを緩い型に設定します。これは任意のプロパティが設定できることを意味します。
func (ty *ObjectType) Loose() {
	ty.Mapped = UnknownType{}
}

func (ty *ObjectType) String() string {
	if !ty.IsStrict() {
		if ty.IsLoose() {
			return "object"
		}
		return fmt.Sprintf("{string => %s}", ty.Mapped.String())
	}

	ps := make([]string, 0, len(ty.Props))
	for n := range ty.Props {
		ps = append(ps, n)
	}
	sort.Strings(ps)

	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, p := range ps {
		if first {
			first = false
		} else {
			b.WriteString("; ")
		}
		b.WriteString(p)
		b.WriteString(": ")
		b.WriteString(ty.Props[p].String())
	}
	b.WriteByte('}')

	return b.String()
}

// Assignable は他の型がこの型に割り当て可能かどうかを返します。
// 言い換えれば、rhs 型は lhs（レシーバー）型よりも厳密です。
func (ty *ObjectType) Assignable(other ExprType) bool {
	switch other := other.(type) {
	case UnknownType:
		return true
	case *ObjectType:
		if !ty.IsStrict() {
			if !other.IsStrict() {
				return ty.Mapped.Assignable(other.Mapped)
			}
			for _, t := range other.Props {
				if !ty.Mapped.Assignable(t) {
					return false
				}
			}
			return true
		}
		// ty は厳密です

		if !other.IsStrict() {
			for _, t := range ty.Props {
				if !t.Assignable(other.Mapped) {
					return false
				}
			}
			return true
		}
		// ty と other は厳密です

		for n, r := range other.Props {
			if l, ok := ty.Props[n]; !ok || !l.Assignable(r) {
				return false
			}
		}

		return true
	default:
		return false
	}
}

// Merge は二つのオブジェクト型を一つにマージします。
// 他のオブジェクトに未知のプロパティがある場合、それらは現在のオブジェクトにマージされます。
// 両方に同じプロパティがあり、それらが割り当て可能である場合、そのまま残ります。
// そうでない場合、プロパティは any 型にフォールバックします。
func (ty *ObjectType) Merge(other ExprType) ExprType {
	switch other := other.(type) {
	case *ObjectType:
		// ショートカット
		if len(ty.Props) == 0 && other.IsLoose() {
			return other
		}
		if len(other.Props) == 0 && ty.IsLoose() {
			return ty
		}

		mapped := ty.Mapped
		if mapped == nil {
			mapped = other.Mapped
		} else if other.Mapped != nil {
			mapped = mapped.Merge(other.Mapped)
		}

		props := make(map[string]ExprType, len(ty.Props))
		for n, l := range ty.Props {
			props[n] = l
		}
		for n, r := range other.Props {
			if l, ok := props[n]; ok {
				props[n] = l.Merge(r)
			} else {
				props[n] = r
				if mapped != nil {
					mapped = mapped.Merge(r)
				}
			}
		}

		return &ObjectType{
			Props:  props,
			Mapped: mapped,
		}
	default:
		return UnknownType{}
	}
}

// DeepCopy は自身のディープコピーを作成します。その子型も再帰的にコピーされます。
func (ty *ObjectType) DeepCopy() ExprType {
	p := make(map[string]ExprType, len(ty.Props))
	for n, t := range ty.Props {
		p[n] = t.DeepCopy()
	}
	m := ty.Mapped
	if m != nil {
		m = m.DeepCopy()
	}
	return &ObjectType{p, m}
}

// ArrayType は配列のための型です。
type ArrayType struct {
	// Elem は配列の要素の型です。
	Elem ExprType
	// Deref はこの型がオブジェクトのフィルタリング構文（foo.*）から派生した場合に true です。
	Deref bool
}

func (ty *ArrayType) String() string {
	return fmt.Sprintf("array<%s>", ty.Elem.String())
}

// Assignable は他の型がこの型に割り当て可能かどうかを返します。
func (ty *ArrayType) Assignable(other ExprType) bool {
	switch other := other.(type) {
	case UnknownType:
		return true
	case *ArrayType:
		return ty.Elem.Assignable(other.Elem)
	default:
		return false
	}
}

// Merge は二つのオブジェクト型を一つにマージします。
// 他のオブジェクトに未知のプロパティがある場合、それらは現在のオブジェクトにマージされます。
// 両方に同じプロパティがあり、それらが割り当て可能である場合、そのまま残ります。
// そうでない場合、プロパティは any 型にフォールバックします。
func (ty *ArrayType) Merge(other ExprType) ExprType {
	switch other := other.(type) {
	case *ArrayType:
		if _, ok := ty.Elem.(UnknownType); ok {
			return ty
		}
		if _, ok := other.Elem.(UnknownType); ok {
			return other
		}
		return &ArrayType{
			Elem:  ty.Elem.Merge(other.Elem),
			Deref: false, // 配列のデリファレンス型を融合するとき、プロパティのデリファレンスチェーンが途切れることを意味します
		}
	default:
		return UnknownType{}
	}
}

// DeepCopy は自身のディープコピーを作成します。その子型も再帰的にコピーされます。
func (ty *ArrayType) DeepCopy() ExprType {
	return &ArrayType{ty.Elem.DeepCopy(), ty.Deref}
}

// EqualTypes は二つの型が等しいかどうかを返します。
func EqualTypes(l, r ExprType) bool {
	return l.Assignable(r) && r.Assignable(l)
}
