export interface Column<T> {
  key: string
  label: string
  align?: 'left' | 'right' | 'center'
  sortable?: boolean
  width?: string
  /** 정렬에 쓸 값. 없으면 row[key] 를 그대로 쓴다. */
  sortValue?: (row: T) => number | string
}
