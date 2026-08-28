"""Seed realistic community blog posts."""
import sys
sys.path.insert(0, ".")

from app.database import SessionLocal, init_db
from app.models.blog_post import BlogPost

POSTS = [
    {
        "slug": "things-i-learned-building-my-first-side-project",
        "title": "Things I Learned Building My First Side Project",
        "author": "alex_m",
        "category": "Projects",
        "summary": "Six months, one product, and more lessons than I expected.",
        "content": """I spent six months building my first real side project. Here is everything that surprised me along the way.

The biggest lesson was that shipping matters more than perfect. I rewrote the backend three times before realizing nobody cared what database I used. They cared whether the thing worked.

Start with a problem you actually have. Every tutorial says this. I ignored it twice. The third time, I built something for my own workflow and it was infinitely easier to stay motivated.

Talk to users early. I waited until the product felt ready. It never felt ready. The people I eventually showed it to pointed out problems within five minutes that I had been blind to for months.

Marketing is not separate from building. I assumed that if I built something good, people would find it. They did not. Distribution is a skill. Learn it alongside the product.

Finally: finish things. A half-built project teaches you less than a shipped one. Even a quiet launch is a launch.""",
        "reading_time": 4,
        "published": True,
        "views": 142,
    },
    {
        "slug": "how-i-finally-fixed-my-sleep-schedule",
        "title": "How I Finally Fixed My Sleep Schedule (After Years of Trying)",
        "author": "priya_k",
        "category": "Personal",
        "summary": "What actually worked after years of conventional advice not sticking.",
        "content": """I have tried every sleep hack in existence. Blue light glasses, no screens after 8pm, melatonin, weighted blankets, white noise machines. Some helped a little. None fixed it.

What finally worked for me was embarrassingly simple: consistent wake time.

Not bedtime, wake time. Every day, including weekends, I get up at the same hour. No exceptions for late nights. The first two weeks were rough. After that, my body started getting tired at a reasonable hour on its own.

The second thing that helped was giving up on the idea of perfect sleep. Some nights are bad. That is normal. Stressing about bad sleep makes sleep worse. Accept the occasional rough night and move on.

Third: the bedroom is only for sleeping. This one I resisted for years because I work from home and space is limited. But I moved my desk out of the bedroom and the difference was immediate.

None of this is revolutionary. All of it required actually doing it consistently, which is the hard part.""",
        "reading_time": 5,
        "published": True,
        "views": 218,
    },
    {
        "slug": "the-best-tools-i-discovered-this-month",
        "title": "The Best Tools I Discovered This Month",
        "author": "dev_tom",
        "category": "Tools",
        "summary": "A curated list of tools worth trying, from someone who tries too many tools.",
        "content": """Every month I try to document the most useful things I stumble across. Here is what made the cut this month.

Obsidian: I resisted plain-text note apps for years. Now I cannot imagine not using one. The graph view is fun but the real value is just files you actually own.

Excalidraw: A whiteboard tool that produces diagrams that look hand-drawn. Perfect for architecture diagrams you share in docs where overly polished graphics feel weird.

Warp: A terminal with actually good UX. I was skeptical but the command history search alone converted me.

Raycast: A launcher that has quietly replaced half a dozen other tools I was running. Clipboard history, snippets, window management. All in one place.

Penpot: Open source design tool. Not Figma, but close enough for most work and entirely self-hostable.

What tools have you discovered recently? Drop a comment.""",
        "reading_time": 3,
        "published": True,
        "views": 89,
    },
    {
        "slug": "thoughts-on-learning-programming-as-an-adult",
        "title": "Thoughts on Learning Programming as an Adult",
        "author": "mia_writes",
        "category": "Learning",
        "summary": "It is harder and more rewarding than the tutorials suggest.",
        "content": """I started learning to code at 34. Every resource I found seemed aimed at either children or people who already knew how to code.

The thing nobody tells you about adult learning is that you have more to unlearn. You have existing mental models that do not map to how programming works. This makes the early stages frustrating in a way that is different from how it is frustrating for younger learners.

But there are advantages too. Adults are better at understanding why something matters. I did not need to be sold on the value of learning. I could see it clearly. That made it easier to push through the hard parts.

Practical advice that helped me:

Build something you actually want to exist. Tutorials are fine for syntax. Real projects teach you real things.

Find a community. I found a small group of people learning at the same level. Being able to ask basic questions without judgment was worth more than any course.

Accept that it takes years. Not days, not weeks. Years. That is not discouraging. It means there is always more to learn, which keeps it interesting.""",
        "reading_time": 6,
        "published": True,
        "views": 301,
    },
    {
        "slug": "my-weekend-photography-setup",
        "title": "My Weekend Photography Setup",
        "author": "sam_lens",
        "category": "Personal",
        "summary": "What I actually carry when I want to take photos without overthinking it.",
        "content": """I used to overthink photography gear. Multiple bodies, a bag full of lenses, always convinced the right focal length was the one I had left at home.

Now I bring one camera and one lens. That is it.

The camera is a mirrorless body that is light enough that I do not resent carrying it. The lens is a 35mm equivalent. It forces me to move my feet instead of zooming, which has made my composition better.

The best photography gear is what you actually bring. The camera that stays home because it is heavy and complicated produces zero photos.

For editing, I do almost everything in Lightroom on my phone now. It is good enough. The gap between phone editing and desktop editing has closed significantly.

The most important thing I have learned: take more photos of boring days. The ones that feel worth photographing always get photographed. It is the ordinary Tuesday afternoons that you will wish you had captured.""",
        "reading_time": 4,
        "published": True,
        "views": 67,
    },
    {
        "slug": "why-i-switched-from-notion-to-plain-text",
        "title": "Why I Switched from Notion to Plain Text",
        "author": "alex_m",
        "category": "Productivity",
        "summary": "Complexity creep, ownership anxiety, and the relief of simpler tools.",
        "content": """I was a heavy Notion user for two years. Intricate databases, linked views, custom templates. I had built something genuinely impressive that I almost never looked at.

The problem with Notion is that maintaining the system becomes the work. I spent more time organizing my notes than using them.

I switched to plain text files stored in a folder. They open instantly. They work offline. I own them. They will work on whatever operating system I use in ten years.

I use one folder for active notes and one for reference. File names are descriptive. Search does the rest. I have stopped building systems and started writing things down.

This is not advice to abandon your tools. It is a reminder that the goal is to capture and use ideas, not to maintain a beautiful system for capturing ideas.

Simpler tools that you actually use beat powerful tools that you avoid because they require setup.""",
        "reading_time": 4,
        "published": True,
        "views": 195,
    },
]

def main():
    init_db()
    db = SessionLocal()
    count = db.query(BlogPost).filter(BlogPost.published == True).count()
    print(f"Existing published posts: {count}")

    added = 0
    for p in POSTS:
        existing = db.query(BlogPost).filter(BlogPost.slug == p["slug"]).first()
        if not existing:
            post = BlogPost(**p)
            db.add(post)
            added += 1

    db.commit()
    total = db.query(BlogPost).filter(BlogPost.published == True).count()
    print(f"Added {added} posts. Total published: {total}")
    db.close()

if __name__ == "__main__":
    main()
