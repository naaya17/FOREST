import os
import openai

def main():
    openai.api_key = os.getenv("OPENAI_API_KEY")
    client = openai.Client()


    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {
                "role": "user",
                "content": "Write a haiku about recursion in programming."
            }
        ]
    )

    print(completion.choices[0].message)

if __name__ == '__main__':
    main()