package bad

type T[K any] struct{}

func Undocumented() {}

// wrong name in the comment.
func Named() {}

func (T[K]) Method() {}

func (*T[K]) PtrMethod() {}
