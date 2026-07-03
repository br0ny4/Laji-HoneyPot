import React from 'react';

type SkeletonVariant = 'card' | 'table' | 'text';

interface SkeletonProps {
  variant?: SkeletonVariant;
  /** 行数（table 和 text 变体使用） */
  rows?: number;
  /** 列数（table 变体使用） */
  cols?: number;
}

const Skeleton: React.FC<SkeletonProps> = ({ variant = 'text', rows = 3, cols = 4 }) => {
  if (variant === 'card') {
    return (
      <div className="skeleton-card">
        <div className="skeleton-pulse skeleton-card-title" />
        <div className="skeleton-pulse skeleton-card-value" />
      </div>
    );
  }

  if (variant === 'table') {
    return (
      <div className="skeleton-table">
        <div className="skeleton-table-header">
          {Array.from({ length: cols }).map((_, i) => (
            <div key={i} className="skeleton-pulse skeleton-th" />
          ))}
        </div>
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="skeleton-table-row">
            {Array.from({ length: cols }).map((_, c) => (
              <div key={c} className="skeleton-pulse skeleton-td" />
            ))}
          </div>
        ))}
      </div>
    );
  }

  // text variant
  return (
    <div className="skeleton-text-block">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="skeleton-pulse skeleton-text-line"
          style={{ width: i === rows - 1 ? '60%' : '100%' }}
        />
      ))}
    </div>
  );
};

export default Skeleton;
