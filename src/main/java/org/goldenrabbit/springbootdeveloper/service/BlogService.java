package org.goldenrabbit.springbootdeveloper.service;

import lombok.RequiredArgsConstructor;
import org.goldenrabbit.springbootdeveloper.domain.Article;
import org.goldenrabbit.springbootdeveloper.dto.AddArticleRequest;
import org.goldenrabbit.springbootdeveloper.dto.UpdateArticleRequest;
import org.goldenrabbit.springbootdeveloper.repository.BlogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RequiredArgsConstructor
@Service
public class BlogService {
    private final BlogRepository blogRepository;


    public Article save(AddArticleRequest request) {
        return blogRepository.save(request.toEntity());
    }

    public List<Article> findAll() {
        return blogRepository.findAll();
    }

    public Article findById(long id) {
        return blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not fount : " + id));
    }

    public void delete(long id) {
        blogRepository.deleteById(id);
    }

    @Transactional
    public Article update(long id, UpdateArticleRequest request) {
        Article article = blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not found : " + id));
        article.update(request.getTitle(), request.getContent());

        return article;
    }

}
