package com.security.guard.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class GitHubPrPayload {

    private String action;

    @JsonProperty("pull_request")
    private PullRequest pullRequest;

    private Repository repository;

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public PullRequest getPullRequest() { return pullRequest; }
    public void setPullRequest(PullRequest pullRequest) { this.pullRequest = pullRequest; }
    public Repository getRepository() { return repository; }
    public void setRepository(Repository repository) { this.repository = repository; }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PullRequest {
        private Long number;
        private String title;
        private String state;

        @JsonProperty("html_url")
        private String htmlUrl;

        @JsonProperty("diff_url")
        private String diffUrl;

        private Head head;
        private Base base;
        private User user;

        public Long getNumber() { return number; }
        public void setNumber(Long number) { this.number = number; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getState() { return state; }
        public void setState(String state) { this.state = state; }
        public Head getHead() { return head; }
        public void setHead(Head head) { this.head = head; }
        public Base getBase() { return base; }
        public void setBase(Base base) { this.base = base; }
        public User getUser() { return user; }
        public void setUser(User user) { this.user = user; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Head {
        private String sha;
        private String ref;
        private Repository repo;

        public String getSha() { return sha; }
        public void setSha(String sha) { this.sha = sha; }
        public String getRef() { return ref; }
        public void setRef(String ref) { this.ref = ref; }
        public Repository getRepo() { return repo; }
        public void setRepo(Repository repo) { this.repo = repo; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Base {
        private String sha;
        private String ref;

        public String getSha() { return sha; }
        public void setSha(String sha) { this.sha = sha; }
        public String getRef() { return ref; }
        public void setRef(String ref) { this.ref = ref; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Repository {
        @JsonProperty("full_name")
        private String fullName;

        @JsonProperty("clone_url")
        private String cloneUrl;

        private String name;

        public String getFullName() { return fullName; }
        public void setFullName(String fullName) { this.fullName = fullName; }
        public String getCloneUrl() { return cloneUrl; }
        public void setCloneUrl(String cloneUrl) { this.cloneUrl = cloneUrl; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class User {
        private String login;
        private String email;

        public String getLogin() { return login; }
        public void setLogin(String login) { this.login = login; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }
}
