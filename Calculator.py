# Simple 4-function calculator with linear graph feature

import matplotlib.pyplot as plt
import numpy as np

def format_result(value):
    return int(value) if value == int(value) else value

def plot_linear(m, b):
    x = np.linspace(-10, 10, 400)
    y = m * x + b

    plt.figure()
    plt.plot(x, y, label=f"y = {format_result(m)}x + {format_result(b)}")
    plt.axhline(0, color='black', linewidth=0.8)
    plt.axvline(0, color='black', linewidth=0.8)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.title(f"Graph of y = {format_result(m)}x + {format_result(b)}")
    plt.xlabel("x")
    plt.ylabel("y")
    plt.legend()
    plt.show()

print("Simple Calculator")
print("Operations: +  -  *  /  graph")

operator = input("Enter operator (+, -, *, /, graph): ").strip()

if operator == "graph":
    m = float(input("Enter slope (m): "))
    b = float(input("Enter y-intercept (b): "))
    plot_linear(m, b)
else:
    num1 = float(input("Enter first number: "))
    num2 = float(input("Enter second number: "))

    if operator == "+":
        result = num1 + num2
        print("Result:", format_result(result))
    elif operator == "-":
        result = num1 - num2
        print("Result:", format_result(result))
    elif operator == "*":
        result = num1 * num2
        print("Result:", format_result(result))
    elif operator == "/":
        if num2 != 0:
            result = num1 / num2
            print("Result:", format_result(result))
        else:
            print("Error: Cannot divide by zero.")
    else:
        print("Error: Invalid operator.")
