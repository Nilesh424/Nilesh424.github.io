---
layout: default
title: Home # Or Home, or whatever title you want for the homepage

# Enable pagination for this page
pagination:
  enabled: true
---

<h1>{{ page.title }}</h1>
<hr class="cs-hr">


<div class="post-list">
  {% for post in paginator.posts %}
    <article class="post-item">
      <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="post-meta">Posted on {{ post.date | date: "%B %d, %Y" }}</p>
      <div class="post-excerpt">
        {{ post.excerpt }}
      </div>
      <p><a href="{{ post.url | relative_url }}">Read More &raquo;</a></p>
    </article>
    {% unless forloop.last %}<hr class="cs-hr" style="margin: 2em 0;">{% endunless %}
  {% endfor %}
</div>

<hr class="cs-hr">


<div class="pagination-nav" style="text-align: center; margin: 2em 0;">
  {% if paginator.previous_page %}
    <a href="{{ paginator.previous_page_path | relative_url }}" class="cs-btn">&laquo; Newer Posts</a>
  {% else %}<span style="color: #888;">&laquo; Newer Posts</span>{% endif %}

  <span style="margin: 0 1em;"> Page {{ paginator.page }} of {{ paginator.total_pages }} </span>

  {% if paginator.next_page %}
    <a href="{{ paginator.next_page_path | relative_url }}" class="cs-btn">Older Posts &raquo;</a>
  {% else %}<span style="color: #888;">Older Posts &raquo;</span>{% endif %}
</div>