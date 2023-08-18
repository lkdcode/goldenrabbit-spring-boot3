package org.goldenrabbit.springbootdeveloper.controller;

import lombok.RequiredArgsConstructor;
import org.goldenrabbit.springbootdeveloper.domain.Article;
import org.goldenrabbit.springbootdeveloper.dto.AddArticleRequest;
import org.goldenrabbit.springbootdeveloper.dto.ArticleResponse;
import org.goldenrabbit.springbootdeveloper.dto.UpdateArticleRequest;
import org.goldenrabbit.springbootdeveloper.service.BlogService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RequiredArgsConstructor
@RestController
public class BlogApiController {

    private final BlogService blogService;

    @GetMapping("/api/articles")
    public ResponseEntity<?> findAllArticles() {
        List<ArticleResponse> articles = blogService.findAll()
                .stream()
                .map(ArticleResponse::new)
                .toList();

        return ResponseEntity.ok()
                .body(articles);
    }

    @GetMapping("api/articles/{id}")
    public ResponseEntity<?> findArticle(@PathVariable(name = "id") long id) {
        Article article = blogService.findById(id);

        return ResponseEntity.ok()
                .body(new ArticleResponse(article));
    }

    @PostMapping("/api/articles")
    public ResponseEntity<?> addArticle(@RequestBody AddArticleRequest request) {
        Article savedArticle = blogService.save(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(savedArticle);
    }

    @DeleteMapping("/api/articles/{id}")
    public ResponseEntity<?> deleteArticle(@PathVariable(name = "id") long id) {
        blogService.delete(id);

        return ResponseEntity.ok().build();
    }

    @PutMapping("/api/articles/{id}")
    public ResponseEntity<?> updateArticle(@PathVariable(name = "id") long id,
                                           @RequestBody UpdateArticleRequest request) {
        Article updatedArticle = blogService.update(id, request);

        return ResponseEntity.ok().body(updatedArticle);
    }

}
