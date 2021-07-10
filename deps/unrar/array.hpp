#ifndef _RAR_ARRAY_
#define _RAR_ARRAY_

extern ErrorHandler ErrHandler;

template <class T> class Array
{
  private:
    T *Buffer;
    size_t BufSize;
    size_t AllocSize;
    size_t MaxSize;
    bool Secure; // Clean memory if true.
  public:
    Array();
    Array(size_t Size);
    Array(const Array &Src); // Copy constructor.
    ~Array();
    inline void CleanData();
    inline T& operator [](size_t Item) const;
    inline T* operator + (size_t Pos);
    inline size_t Size(); // Returns the size in items, not in bytes.
    void Add(size_t Items);
    void Alloc(size_t Items);
    void Reset();
    void SoftReset();
    void operator = (Array<T> &Src);
    void Push(T Item);
    void Append(T *Item,size_t Count);
    T* Addr(size_t Item) {return Buffer+Item;}
    void SetMaxSize(size_t Size) {MaxSize=Size;}
    T* Begin() {return Buffer;}
    T* End() {return Buffer==NULL ? NULL:Buffer+BufSize;}
    void SetSecure() {Secure=true;}
};


template <class T> void Array<T>::CleanData()
{
  Buffer=NULL;
  BufSize=0;
  AllocSize=0;
  MaxSize=0;
  Secure=false;
}


template <class T> Array<T>::Array()
{
  CleanData();
}


template <class T> Array<T>::Array(size_t Size)
{
  CleanData();
  Add(Size);
}


// Copy constructor in case we need to pass an object as value.
template <class T> Array<T>::Array(const Array &Src)
{
  CleanData();
  Alloc(Src.BufSize);
  if (Src.BufSize!=0)
    memcpy((void *)Buffer,(void *)Src.Buffer,Src.BufSize*sizeof(T));
}


template <class T> Array<T>::~Array()
{
  if (Buffer!=NULL)
  {
    if (Secure)
      cleandata(Buffer,AllocSize*sizeof(T));
    free(Buffer);
  }
}


template <class T> inline T& Array<T>::operator [](size_t Item) const
{
  return Buffer[Item];
}


template <class T> inline T* Array<T>::operator +(size_t Pos)
{
  return Buffer+Pos;
}


template <class T> inline size_t Array<T>::Size()
{
  return BufSize;
}


template <class T> void Array<T>::Add(size_t Items)
{
  BufSize+=Items;
  if (BufSize>AllocSize)
  {
    if (MaxSize!=0 && BufSize>MaxSize)
    {
      ErrHandler.GeneralErrMsg(L"Maximum allowed array size (%u) is exceeded",MaxSize);
      ErrHandler.MemoryError();
    }

    size_t Suggested=AllocSize+AllocSize/4+32;
    size_t NewSize=Max(BufSize,Suggested);

    T *NewBuffer;
    if (Secure)
    {
      NewBuffer=(T *)malloc(NewSize*sizeof(T));
      if (NewBuffer==NULL)
        ErrHandler.MemoryError();
      if (Buffer!=NULL)
      {
        memcpy(NewBuffer,Buffer,AllocSize*sizeof(T));
        cleandata(Buffer,AllocSize*sizeof(T));
        free(Buffer);
      }
    }
    else
    {
      NewBuffer=(T *)realloc(Buffer,NewSize*sizeof(T));
      if (NewBuffer==NULL)
        ErrHandler.MemoryError();
    }
    Buffer=NewBuffer;
    AllocSize=NewSize;
  }
}


template <class T> void Array<T>::Alloc(size_t Items)
{
  if (Items>AllocSize)
    Add(Items-BufSize);
  else
    BufSize=Items;
}


template <class T> void Array<T>::Reset()
{
  if (Buffer!=NULL)
  {
    free(Buffer);
    Buffer=NULL;
  }
  BufSize=0;
  AllocSize=0;
}


// Reset buffer size, but preserve already allocated memory if any,
// so we can reuse it without wasting time to allocation.
template <class T> void Array<T>::SoftReset()
{
  BufSize=0;
}


template <class T> void Array<T>::operator =(Array<T> &Src)
{
  Reset();
  Alloc(Src.BufSize);
  if (Src.BufSize!=0)
    memcpy((void *)Buffer,(void *)Src.Buffer,Src.BufSize*sizeof(T));
}


template <class T> void Array<T>::Push(T Item)
{
  Add(1);
  (*this)[Size()-1]=Item;
}


template <class T> void Array<T>::Append(T *Items,size_t Count)
{
  size_t CurSize=Size();
  Add(Count);
  memcpy(Buffer+CurSize,Items,Count*sizeof(T));
}

#endif
