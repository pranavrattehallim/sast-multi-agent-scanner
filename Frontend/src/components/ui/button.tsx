import { cn } from "@/lib/utils"
export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "outline"
}
const Button = ({ className, variant = "default", ...props }: ButtonProps) => (
  <button
    className={cn(
      "inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50 h-9 px-4 py-2",
      variant === "default" && "bg-primary text-primary-foreground shadow hover:bg-primary/90",
      variant === "outline" && "border border-input bg-background shadow-sm hover:bg-accent hover:text-accent-foreground",
      className
    )}
    {...props}
  />
)
export { Button }
