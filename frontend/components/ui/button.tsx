import type { ButtonHTMLAttributes, ReactNode } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
  children: ReactNode;
}

export function Button({ variant = "primary", children, className = "", ...rest }: ButtonProps) {
  const base =
    variant === "primary"
      ? "bg-soc-accent text-black hover:brightness-110"
      : "border border-soc-border text-soc-text hover:bg-soc-border/50";
  return (
    <button
      className={`rounded px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 ${base} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}
