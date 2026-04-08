# Simple 4-function calculator

print("Simple Calculator")
print("Operations: +  -  *  /")

num1 = float(input("Enter first number: "))
operator = input("Enter operator (+, -, *, /): ")
num2 = float(input("Enter second number: "))

def format_result(value):
    return int(value) if value == int(value) else value

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